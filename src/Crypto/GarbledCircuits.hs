{-# LANGUAGE FlexibleInstances, RankNTypes #-}

module Crypto.GarbledCircuits (
    -- * Garbled Circuit datatypes
    Circuit (..)
  , Program (..)
  , Party (..)
  , Ref (..)
  -- * The garbled circuit protocols
  , Connection (..)
  , garblerProto
  , evaluatorProto
  -- ** Simple socket connection
  , connectTo
  , listenAt
  , simpleConn
  )
where

import Crypto.GarbledCircuits.GarbledGate
import Crypto.GarbledCircuits.TruthTable
import Crypto.GarbledCircuits.Eval
import Crypto.GarbledCircuits.Types
import Crypto.GarbledCircuits.Util
import Crypto.GarbledCircuits.Network
import Crypto.GarbledCircuits.ObliviousTransfer

import           Control.Monad
import           Crypto.Cipher.AES128 (AESKey128)
import           Data.Functor
import qualified Data.ByteString.Char8 as BS
import           Data.Serialize (decode, encode, Serialize)
import           Network.Socket hiding (send, recv)
import           Network.BSD
import           System.IO
import           Text.Printf

garblerProto :: Program Circuit -> [Bool] -> Connection -> IO [Bool]
garblerProto prog inp conn = do
    -- 1. Garbler garble the circuits
    --    gg is the garbled circuits, and ctx contains the table to know what bit an input wire represent for.
    (gg, ctx) <- garble prog
    traceM "[garblerProto] circuit garbled"
    -- 2. Garbler gets the wires for his inputs
    let myWires    = inputWires Garbler   gg ctx inp
      --  Garbler gets the input wire pairs for Evaluator's inputs. An input paire is two wires, one for False, one for True
        theirPairs = map asTuple $ inputPairs Evaluator gg ctx
    printf "[garblerProto] sending garbled circuit (size=%d)\n" (byteSize (halfGates gg))
    -- 4. Garbler send the halfGates of the garbled circuits to Evaluator though their connection
    send conn (halfGates gg)
    traceM "[garblerProto] sending my input wires"
    -- 6. Garbler send his input wires to Evaluator
    send conn myWires
    traceM "[garblerProto] sending key"
    -- 8. Garbler send the key of the garbled circuits to Evaluator (without the key, one can't evaluator the garbled circuits)
    send conn (ctx_key ctx)
    traceM "[garblerProto] performing OT"
    -- 10. Garbler send Evaluator's input wire through OT
    otSend conn (ctx_key ctx) theirPairs
    traceM "[garblerProto] recieving output"
    -- 15. Garbler receives the output wires
    wires <- recv conn
    --  Garbler looks up the table to know the exact number of the wires
    let result = map (ungarble ctx) wires
    traceM "[garblerProto] sending ungarbled output"
    --  16. Garlber optionally sends the clear text result to Evaluator. If Evaluator doesn't trust Garlber, they will do again the other way around.
    send conn result
    printConnectionInfo conn
    return result

evaluatorProto :: Program Circuit -> [Bool] -> Connection -> IO [Bool]
evaluatorProto prog inp conn = do
    -- 3 Evaluator builds the TruthTable from the circuits
    let tt = circ2tt prog
    traceM "[evaluatorProto] recieving circuit"
    -- 5. Evaluator receives the halfGates of the garbled circuits
    hgs <- recv conn :: IO [(Wirelabel,Wirelabel)]
    traceM "[evaluatorProto] recieving garbler input wires"
    -- 7 Evaluator receives Garbler's input wires
    inpGb <- recv conn :: IO [Wirelabel]
    traceM "[evaluatorProto] recieving key"
    -- 9 Evaluator recieves the key of the garbled circuits
    key <- recv conn :: IO AESKey128
    traceM "[evaluatorProto] performing OT"
    -- 11 Evaluator get Evaluator's input wire through OT
    inpEv <- otRecv conn key inp
    traceM "[evaluatorProto] evaluating garbled circuit"
    -- 12 Evaluator rebuild garbled circuits with TruthTable and halfGates
    let gg  = reconstruct tt hgs
    -- 13 Evaluator evaluates the garbled circuits with the key and both input wires from Evaluator and Garbler.
    --    the evaluation result is the output wires which is still encrypted.
        out = eval gg key inpGb inpEv
    traceM ("[evaluatorProto] output =\n" ++ showOutput (prog_output gg) out)
    traceM "[evaluatorProto] sending output wires"
    -- 14 Evaluator sends the output wires to Garbler
    send conn out
    traceM "[evaluatorProto] recieving ungarbled output"
    -- 17. Evaluator receives clear text result
    result <- recv conn
    printConnectionInfo conn
    return result

--------------------------------------------------------------------------------
-- ot

showOutput :: [Ref GarbledGate] -> [Wirelabel] -> String
showOutput refs = init . unlines . zipWith (\r w -> "\t" ++ show r ++ " " ++ showWirelabel w) refs

asTuple :: WirelabelPair -> (Wirelabel, Wirelabel)
asTuple p = (wlp_false p, wlp_true p)
