{-# LANGUAGE TemplateHaskell #-}

module Main where

import Test.QuickCheck
import Test.QuickCheck.Monadic

import Data.Word

import qualified Data.ByteArray as BA

import qualified Data.ByteString as S
import           Data.ByteString (ByteString)

import qualified Crypto.Hash
import           Crypto.Hash (Digest, SHA256)

import qualified Crypto.PubKey.RSA.PSS as PSS
import qualified Crypto.PubKey.RSA as RSA

import           PrivateKey
import           OpenSSL

import           Control.Monad

newtype SomeInput = SomeInput ByteString deriving Show

instance Arbitrary SomeInput where
  arbitrary = do
    len <- choose (0, 65536)
    ws  <- take len <$> infiniteListOf arbitrary
    return . SomeInput . S.pack $ ws

prop_ssl_pss_verify_dot_sign_is_true (SomeInput input) = monadicIO $ do
  r <- run $ do
    priv <- generatePrivateKey
    let dgst = BA.convert (Crypto.Hash.hash input :: Digest SHA256)
    sig  <- pkeyutlSignPss priv dgst
    pkeyutlVerifyPss priv dgst sig
  assert (r == True)

prop_cryptonite_pss_verify (SomeInput input) = monadicIO $ do
  r <- run $ do
    priv <- generatePrivateKey
    let dgst = BA.convert (Crypto.Hash.hash input :: Digest SHA256)
    sig  <- pkeyutlSignPss priv dgst
    return (PSS.verify (PSS.defaultPSSParams Crypto.Hash.SHA256) (RSA.private_pub priv) input sig)
  assert (r == True)

return []
runTests = $quickCheckAll

main :: IO ()
main = void runTests 
