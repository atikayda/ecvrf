{-# LANGUAGE OverloadedStrings #-}
module Main (main) where

import Crypto.ECVRF (prove, verify, proofToHash)
import Data.Aeson ((.:), eitherDecodeStrict', withObject, FromJSON(..))
import qualified Data.ByteString as BS
import qualified Data.Text as T
import System.Exit (exitFailure, exitSuccess)
import System.FilePath ((</>))

data VectorFile = VectorFile
  { vfVectors         :: [PositiveVector]
  , vfNegativeVectors :: [NegativeVector]
  }

instance FromJSON VectorFile where
  parseJSON = withObject "VectorFile" $ \o ->
    VectorFile <$> o .: "vectors" <*> o .: "negative_vectors"

data PositiveVector = PositiveVector
  { pvLabel :: T.Text
  , pvSK    :: T.Text
  , pvPK    :: T.Text
  , pvAlpha :: T.Text
  , pvPi    :: T.Text
  , pvBeta  :: T.Text
  }

instance FromJSON PositiveVector where
  parseJSON = withObject "PositiveVector" $ \o ->
    PositiveVector <$> o .: "label" <*> o .: "sk" <*> o .: "pk"
                   <*> o .: "alpha" <*> o .: "pi" <*> o .: "beta"

data NegativeVector = NegativeVector
  { nvDescription :: T.Text
  , nvPK          :: T.Text
  , nvAlpha       :: T.Text
  , nvPi          :: T.Text
  }

instance FromJSON NegativeVector where
  parseJSON = withObject "NegativeVector" $ \o ->
    NegativeVector <$> o .: "description" <*> o .: "pk"
                   <*> o .: "alpha" <*> o .: "pi"

hexDecode :: T.Text -> BS.ByteString
hexDecode = BS.pack . go . T.unpack
  where
    go [] = []
    go [_] = error "odd-length hex string"
    go (a:b:rest) = fromIntegral (hexVal a * 16 + hexVal b) : go rest
    hexVal c
      | c >= '0' && c <= '9' = fromEnum c - fromEnum '0'
      | c >= 'a' && c <= 'f' = fromEnum c - fromEnum 'a' + 10
      | c >= 'A' && c <= 'F' = fromEnum c - fromEnum 'A' + 10
      | otherwise = error $ "invalid hex char: " ++ [c]

hexEncode :: BS.ByteString -> String
hexEncode = concatMap (\b -> [hexChar (fromIntegral b `div` 16), hexChar (fromIntegral b `mod` 16)]) . BS.unpack
  where
    hexChar n
      | n < 10    = toEnum (fromEnum '0' + n)
      | otherwise = toEnum (fromEnum 'a' + n - 10)

main :: IO ()
main = do
  let vectorsPath = ".." </> "vectors" </> "vectors.json"
  raw <- BS.readFile vectorsPath
  case eitherDecodeStrict' raw of
    Left err -> do
      putStrLn $ "Failed to parse vectors.json: " ++ err
      exitFailure
    Right vf -> do
      (pPass, pFail) <- runPositiveVectors (vfVectors vf)
      (nPass, nFail) <- runNegativeVectors (vfNegativeVectors vf)
      putStrLn ""
      putStrLn $ "Positive vectors: " ++ show pPass ++ " passed, " ++ show pFail ++ " failed"
      putStrLn $ "Negative vectors: " ++ show nPass ++ " passed, " ++ show nFail ++ " failed"
      if pFail == 0 && nFail == 0
        then do putStrLn "ALL TESTS PASSED"; exitSuccess
        else do putStrLn "SOME TESTS FAILED"; exitFailure

runPositiveVectors :: [PositiveVector] -> IO (Int, Int)
runPositiveVectors = go 0 0
  where
    go p f [] = return (p, f)
    go p f (v:vs) = do
      let sk    = hexDecode (pvSK v)
          alpha = hexDecode (pvAlpha v)
          expectedPi   = T.unpack (pvPi v)
          expectedBeta = T.unpack (pvBeta v)
          label = T.unpack (pvLabel v)

      -- Test prove
      case prove sk alpha of
        Nothing -> do
          putStrLn $ "  FAIL [prove] " ++ label ++ ": prove returned Nothing"
          go p (f + 1) vs
        Just pi_ -> do
          let gotPi = hexEncode pi_
          if gotPi /= expectedPi
            then do
              putStrLn $ "  FAIL [prove] " ++ label
              putStrLn $ "    expected: " ++ expectedPi
              putStrLn $ "    got:      " ++ gotPi
              go p (f + 1) vs
            else do
              -- Test verify
              let pk = hexDecode (pvPK v)
              case verify pk pi_ alpha of
                Nothing -> do
                  putStrLn $ "  FAIL [verify] " ++ label ++ ": verify returned Nothing"
                  go (p + 1) (f + 1) vs
                Just beta -> do
                  let gotBeta = hexEncode beta
                  if gotBeta /= expectedBeta
                    then do
                      putStrLn $ "  FAIL [beta] " ++ label
                      putStrLn $ "    expected: " ++ expectedBeta
                      putStrLn $ "    got:      " ++ gotBeta
                      go (p + 1) (f + 1) vs
                    else do
                      -- Test proofToHash
                      case proofToHash pi_ of
                        Nothing -> do
                          putStrLn $ "  FAIL [proofToHash] " ++ label
                          go (p + 1) (f + 1) vs
                        Just beta2 ->
                          if hexEncode beta2 /= expectedBeta
                            then do
                              putStrLn $ "  FAIL [proofToHash] " ++ label
                              go (p + 1) (f + 1) vs
                            else do
                              putStrLn $ "  PASS " ++ label
                              go (p + 1) f vs

runNegativeVectors :: [NegativeVector] -> IO (Int, Int)
runNegativeVectors = go 0 0
  where
    go p f [] = return (p, f)
    go p f (v:vs) = do
      let pk    = hexDecode (nvPK v)
          alpha = hexDecode (nvAlpha v)
          pi_   = hexDecode (nvPi v)
          desc  = T.unpack (nvDescription v)
      case verify pk pi_ alpha of
        Nothing -> do
          putStrLn $ "  PASS (rejected) " ++ desc
          go (p + 1) f vs
        Just _ -> do
          putStrLn $ "  FAIL (accepted) " ++ desc
          go p (f + 1) vs
