{-# LANGUAGE GeneralizedNewtypeDeriving #-}

module Garbled.Circuits where

import Garbled.Circuits.Circuit

import Prelude hiding (and, or)
import Control.Monad

--------------------------------------------------------------------------------
-- 8 bit adder example

add1Bit :: Ref -> Ref -> Ref -> CircuitBuilder (Ref, Ref)
add1Bit x y c = do
    s    <- xor x y
    out  <- xor c s
    cout <- bindM2 or (and x y) (and c s)
    return (out, cout)
  where
    bindM2 m a b = do x <- a; y <- b; m x y

addBits :: [Ref] -> [Ref] -> CircuitBuilder ([Ref], Ref)
addBits xs ys = do
    f <- constant False
    builder xs ys f []
  where
    builder [] []         c outs = return (outs, c)
    builder (x:xs) (y:ys) c outs = do 
      (out,c') <- add1Bit x y c
      builder xs ys c' (out:outs)

circ_8BitAdder :: CircuitBuilder [Ref]
circ_8BitAdder = do
    inp1      <- replicateM 8 input
    inp2      <- replicateM 8 input
    (outs, _) <- addBits inp1 inp2
    return outs
