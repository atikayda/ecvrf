module Main where

import qualified Crypto.ECVRF as ECVRF
import qualified Data.ByteString as BS
import Data.Word (Word8)
import Data.Char (digitToInt, intToDigit, toLower, isHexDigit)
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)

hexDecode :: String -> BS.ByteString
hexDecode [] = BS.empty
hexDecode [_] = BS.empty
hexDecode (a:b:rest)
  | isHexDigit a && isHexDigit b =
      BS.cons (fromIntegral $ digitToInt a * 16 + digitToInt b) (hexDecode rest)
  | otherwise = BS.empty

hexEncode :: BS.ByteString -> String
hexEncode = concatMap (\w -> [intToDigit (fromIntegral (w `div` 16)), intToDigit (fromIntegral (w `mod` 16))]) . BS.unpack

readAlpha :: [String] -> Int -> IO String
readAlpha args idx
  | idx < length args && args !! idx == "--alpha-file" && idx + 1 < length args = do
      contents <- readFile (args !! (idx + 1))
      return (strip contents)
  | idx < length args = return (args !! idx)
  | otherwise = do
      hPutStrLn stderr "missing alpha argument"
      exitFailure
  where
    strip = reverse . dropWhile (`elem` ['\n', '\r', ' ']) . reverse

main :: IO ()
main = do
  args <- getArgs
  case args of
    [] -> do
      hPutStrLn stderr "usage: ecvrf-haskell prove|verify ..."
      exitFailure
    ("prove" : skHex : rest) -> do
      alphaHex <- readAlpha rest 0
      let sk = hexDecode skHex
          alpha = hexDecode alphaHex
      case ECVRF.prove sk alpha of
        Nothing -> do
          hPutStrLn stderr "prove failed"
          exitFailure
        Just pi -> case ECVRF.proofToHash pi of
          Nothing -> do
            hPutStrLn stderr "proof_to_hash failed"
            exitFailure
          Just beta ->
            putStrLn $ "{\"pi\":\"" ++ hexEncode pi ++ "\",\"beta\":\"" ++ hexEncode beta ++ "\"}"
    ("verify" : pkHex : piHex : rest) -> do
      alphaHex <- readAlpha rest 0
      let pk = hexDecode pkHex
          pi = hexDecode piHex
          alpha = hexDecode alphaHex
      case ECVRF.verify pk pi alpha of
        Just beta ->
          putStrLn $ "{\"valid\":true,\"beta\":\"" ++ hexEncode beta ++ "\"}"
        Nothing ->
          putStrLn "{\"valid\":false,\"beta\":null}"
    (cmd : _) -> do
      hPutStrLn stderr $ "unknown command: " ++ cmd
      exitFailure
