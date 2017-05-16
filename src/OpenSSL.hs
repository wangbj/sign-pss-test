{-# LANGUAGE OverloadedStrings #-}

module OpenSSL (
    pkeyutlSignPss
  , pkeyutlVerifyPss
  , generatePrivateKey
    ) where

import qualified Data.ByteString as S
import qualified Data.ByteString.Char8 as C
import           Data.ByteString (ByteString)
import qualified Crypto.PubKey.OpenSsh as SSH

import qualified Crypto.PubKey.RSA as RSA

import Control.Concurrent
import Control.Exception
import System.Process
import System.Posix.Temp
import System.IO
import System.Directory
import System.Exit
import Data.Maybe
import Data.List (intercalate, find)

import PrivateKey

pkeyOpts = [ "rsa_padding_mode:pss"
          , "rsa_pss_saltlen:-1"
          , "digest:sha256" ]

pssOpts = intercalate " " $ map  (\opt -> "-pkeyopt " ++ opt) pkeyOpts

-- sign pss using openSSL pkeyutl, may throw exceptions
pkeyutlSignPss :: PrivateKey             -- ^private key
               -> ByteString             -- ^input data
               -> IO ByteString          -- ^signature
pkeyutlSignPss priv input = 
  withTempFile "privKey" $ \privKeyFile ->
  withTempFile "inputdata" $ \inputFile ->
  withTempFile "outsig" $ \sigFile -> do
    S.writeFile inputFile input
    writePrivateKey privKeyFile priv
    withProcess (silent ("openssl pkeyutl " ++ pssOpts ++ " -sign " ++ " -inkey " ++ privKeyFile ++ " -in " ++ inputFile ++ " -out " ++ sigFile)) $ \pf ->
      S.readFile sigFile

-- verify pss signing using openSSL pkeyutl, may throw exceptions
pkeyutlVerifyPss :: PrivateKey          -- ^private key
                 -> ByteString          -- ^input data
                 -> ByteString          -- ^signature
                 -> IO Bool             -- ^result
pkeyutlVerifyPss priv input sig = 
  withTempFile "privKey" $ \privKeyFile ->
  withTempFile "inputdata" $ \inputFile ->
  withTempFile "signature" $ \sigFile -> do
  withTempFile "output" $ \outputFile -> do  
    S.writeFile inputFile input
    S.writeFile sigFile sig
    writePrivateKey privKeyFile priv
    withProcess_ (silent ("openssl pkeyutl " ++ pssOpts ++ " -verify " ++ " -inkey " ++ privKeyFile ++ " -in " ++ inputFile ++ " -sigfile " ++ sigFile ++ " -out " ++ outputFile)) $ \pf -> S.readFile outputFile >>= \cmdOutput -> return ("Signature Verified Successfully" `S.isPrefixOf` cmdOutput)

silent s = (shell s) { std_in = NoStream, std_out = NoStream, std_err = CreatePipe }

mkstempFile prefix = bracket (mkstemp prefix) (hClose . snd) (return . fst)

withTempFile :: String -> (FilePath -> IO a) -> IO a
withTempFile prefix f = bracket (mkstempFile prefix) removeFile f

mayThrowIO :: Maybe Handle -> IO a
mayThrowIO (Nothing) = exitFailure
mayThrowIO (Just h) = hGetContents h >>= die

withProcess :: CreateProcess -> (ProcessHandle -> IO a) -> IO a
withProcess p f = bracket (createProcess p) (\(inh, outh, errh, ph) -> (mapM_ hClose (catMaybes [inh, outh, errh]) >> terminateProcess ph)) (\(_, _, errh, ph) -> waitForProcess ph >>= \exitcode -> if exitcode == ExitSuccess then f ph else mayThrowIO errh)

withProcess_ :: CreateProcess -> (ProcessHandle -> IO a) -> IO a
withProcess_ p f = bracket (createProcess p) (\(inh, outh, errh, ph) -> (mapM_ hClose (catMaybes [inh, outh, errh]) >> terminateProcess ph)) (\(_, _, errh, ph) -> waitForProcess ph >> f ph)


data OpenSSLGenRsaFailure = OpenSSLGenRsaFailure String deriving Show

instance Exception OpenSSLGenRsaFailure

generatePrivateKey :: IO PrivateKey
generatePrivateKey = 
  withTempFile "rsaprivate" $ \privKeyFile ->
    withProcess (silent ("openssl genrsa -out " ++ privKeyFile ++ " > /dev/null 2>&1 ")) $ \ph ->
      either (throwIO . OpenSSLGenRsaFailure) return =<< readPrivateKey privKeyFile
