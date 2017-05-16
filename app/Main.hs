module Main where

import qualified Data.ByteString as S
import           Data.ByteString (ByteString)
import Data.Word

import PrivateKey
import OpenSSL

import Control.Monad

import Test.QuickCheck

main :: IO ()
main = do
  priv <- generatePrivateKey
  input <- S.pack <$> generate (take 32 <$> infiniteListOf arbitrary :: Gen [Word8])
  sig <- pkeyutlSignPss priv input
  r   <- pkeyutlVerifyPss priv input sig
  when (not r) (putStrLn "PSS test failed")
