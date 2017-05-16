module PrivateKey (
    PrivateKey
  , readPrivateKey
  , writePrivateKey
  ) where

import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as C
import           Data.ByteString (ByteString)

import qualified Crypto.PubKey.RSA as RSA

import qualified Data.PEM as PEM

import Data.ASN1.Encoding
import Data.ASN1.BinaryEncoding
import Data.ASN1.Types
import Data.Bits

type PrivateKey = RSA.PrivateKey

mapLeft :: (e -> e') -> Either e a -> Either e' a
mapLeft f (Left e) = Left (f e)
mapLeft f (Right a) = Right a

getPrivKeyBer filename = do
  PEM.pemParseBS <$> S.readFile filename >>= \pem_ -> case pem_ of
    Left err  -> return (Left err)
    Right pemList -> case pemList of
      []      -> return (Left "getPrivKey: emtpy PEM data")
      [p]     -> return . Right . PEM.pemContent $ p
      (p:ps)  -> return (Left "getPrivKey: expect just 1 PEM")
  
getPrivKey_ ber = do
  asn1 <- mapLeft show . decodeASN1' BER $ ber
  return asn1

between prefix suffix s = case s of
  [] -> Left "empty list: cannot find prefix"
  (x:xs) -> if x /= prefix then Left ("prefix mis-match, expected: " ++ show prefix ++ ", actual: " ++ show x) else case (reverse xs) of
    [] -> Left ("empty list: cannot find any suffix")
    (y:ys) -> if y /= suffix then Left ("suffix mis-match, expected: " ++ show suffix ++ ", actual: " ++ show y) else Right (reverse ys)

getPrivKeyAsn1 asn1_ = between (Start Sequence) (End Sequence) asn1_ >>= \asn1s_ -> case asn1s_ of
  (IntVal version: IntVal modulus: IntVal pubExponent: IntVal private_d: IntVal private_p: IntVal private_q: IntVal private_dP: IntVal private_dQ: IntVal private_qinv:[]) -> if version == 0 then Right (RSA.PrivateKey (RSA.PublicKey (modulusBytes modulus) modulus (fromIntegral pubExponent)) private_d private_p private_q private_dP private_dQ private_qinv) else Left "version must be 0 in private key file"
  _ -> Left "cannot decode private key file"

modulusBytes :: Integer -> Int
modulusBytes x
  | x >= 256 = 1 + modulusBytes (x `shiftR` 8)
  | x == 0 = 0
  | x < 256 = 1

readPrivateKey :: FilePath -> IO (Either String PrivateKey)
readPrivateKey p = do
  ber <- getPrivKeyBer p
  return (ber >>= getPrivKey_ >>= getPrivKeyAsn1)

writePrivateKey :: FilePath -> PrivateKey -> IO ()
writePrivateKey fp (RSA.PrivateKey (RSA.PublicKey size modulus publicExponent) d p q dp dq qinv) = S.writeFile fp (PEM.pemWriteBS pem)
  where
    asn1s = [Start Sequence, IntVal 0] ++ (map IntVal [modulus, fromIntegral publicExponent, d, p, q, dp, dq, qinv]) ++ [End Sequence]
    bs    = encodeASN1' DER asn1s
    pem   = PEM.PEM "RSA PRIVATE KEY" [] bs
