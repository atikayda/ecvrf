module Crypto.ECVRF
  ( prove
  , verify
  , proofToHash
  , derivePublicKey
  ) where

import qualified Crypto.Hash.SHA256 as SHA256
import Data.Bits (shiftL, shiftR, testBit, (.&.), xor)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)
import Data.Word (Word8)

-- secp256k1 curve parameters
curveP :: Integer
curveP = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F

curveN :: Integer
curveN = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

curveB :: Integer
curveB = 7

curveGx :: Integer
curveGx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798

curveGy :: Integer
curveGy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

suiteByte :: Word8
suiteByte = 0xFE

data Point = Point !Integer !Integer | Infinity
  deriving (Eq, Show)

curveG :: Point
curveG = Point curveGx curveGy

-- Modular arithmetic helpers
modP :: Integer -> Integer
modP x = x `mod` curveP

modN :: Integer -> Integer
modN x = x `mod` curveN

modInv :: Integer -> Integer -> Integer
modInv a m = go a m 1 0
  where
    go _ 0 x _ = x `mod` m
    go old new_ oldS newS =
      let q = old `div` new_
      in go new_ (old - q * new_) newS (oldS - q * newS)

-- Tonelli-Shanks square root mod p (secp256k1 p ≡ 3 mod 4, so use fast path)
modSqrt :: Integer -> Integer -> Maybe Integer
modSqrt n p_
  | n `mod` p_ == 0 = Just 0
  | otherwise =
      let r = modPow n ((p_ + 1) `div` 4) p_
      in if (r * r) `mod` p_ == n `mod` p_ then Just r else Nothing

modPow :: Integer -> Integer -> Integer -> Integer
modPow base_ exp_ m
  | exp_ < 0  = error "negative exponent"
  | exp_ == 0 = 1
  | otherwise = go base_ exp_ 1
  where
    go _ 0 acc = acc
    go b e acc =
      let acc' = if testBit e 0 then (acc * b) `mod` m else acc
      in go ((b * b) `mod` m) (shiftR e 1) acc'

-- Point operations on secp256k1
pointAdd :: Point -> Point -> Point
pointAdd Infinity q = q
pointAdd p_ Infinity = p_
pointAdd (Point x1 y1) (Point x2 y2)
  | x1 == x2 && y1 == modP (negate y2) = Infinity
  | x1 == x2 && y1 == y2 = pointDouble (Point x1 y1)
  | otherwise =
      let s = modP ((y2 - y1) * modInv (x2 - x1) curveP)
          x3 = modP (s * s - x1 - x2)
          y3 = modP (s * (x1 - x3) - y1)
      in Point x3 y3

pointDouble :: Point -> Point
pointDouble Infinity = Infinity
pointDouble (Point x y)
  | y == 0 = Infinity
  | otherwise =
      let s = modP ((3 * x * x) * modInv (2 * y) curveP)
          x3 = modP (s * s - 2 * x)
          y3 = modP (s * (x - x3) - y)
      in Point x3 y3

pointNeg :: Point -> Point
pointNeg Infinity = Infinity
pointNeg (Point x y) = Point x (modP (negate y))

scalarMul :: Integer -> Point -> Point
scalarMul 0 _ = Infinity
scalarMul _ Infinity = Infinity
scalarMul k p_
  | k < 0     = scalarMul (negate k) (pointNeg p_)
  | otherwise = go k p_ Infinity
  where
    go 0 _ acc = acc
    go n q acc =
      let acc' = if testBit n 0 then pointAdd acc q else acc
      in go (shiftR n 1) (pointDouble q) acc'

-- SEC1 point compression (33 bytes)
pointToBytes :: Point -> ByteString
pointToBytes Infinity = error "cannot serialize point at infinity"
pointToBytes (Point x y) =
  let prefix = if testBit y 0 then 0x03 else 0x02 :: Word8
  in BS.cons prefix (i2osp x 32)

-- SEC1 point decompression
bytesToPoint :: ByteString -> Maybe Point
bytesToPoint bs
  | BS.length bs /= 33 = Nothing
  | otherwise =
      let prefix = BS.index bs 0
          xBytes = BS.drop 1 bs
          x = os2ip xBytes
      in if prefix /= 0x02 && prefix /= 0x03
         then Nothing
         else let rhs = modP (modPow x 3 curveP + curveB)
              in case modSqrt rhs curveP of
                   Nothing -> Nothing
                   Just y ->
                     let yEven = if testBit y 0 then modP (negate y) else y
                         yFinal = if prefix == 0x02 then yEven
                                  else modP (negate yEven)
                     in Just (Point x yFinal)

-- Integer to Octet String Primitive (big-endian)
i2osp :: Integer -> Int -> ByteString
i2osp val len_ = BS.pack $ map getByte [len_ - 1, len_ - 2 .. 0]
  where
    getByte i = fromIntegral ((val `shiftR` (i * 8)) .&. 0xFF)

-- Octet String to Integer Primitive (big-endian)
os2ip :: ByteString -> Integer
os2ip = BS.foldl' (\acc b -> acc `shiftL` 8 + fromIntegral b) 0

-- HMAC-SHA256
hmacSHA256 :: ByteString -> ByteString -> ByteString
hmacSHA256 key msg =
  let blockSize = 64
      key' = if BS.length key > blockSize
             then SHA256.hash key
             else key
      paddedKey = key' <> BS.replicate (blockSize - BS.length key') 0
      opad = BS.map (`xor` 0x5C) paddedKey
      ipad = BS.map (`xor` 0x36) paddedKey
  in SHA256.hash (opad <> SHA256.hash (ipad <> msg))

-- RFC 6979 deterministic nonce generation (Section 3.2)
nonceRFC6979 :: ByteString -> ByteString -> Integer
nonceRFC6979 skBytes msgHash =
  let v0 = BS.replicate 32 0x01
      k0 = BS.replicate 32 0x00
      k1 = hmacSHA256 k0 (v0 <> BS.singleton 0x00 <> skBytes <> msgHash)
      v1 = hmacSHA256 k1 v0
      k2 = hmacSHA256 k1 (v1 <> BS.singleton 0x01 <> skBytes <> msgHash)
      v2 = hmacSHA256 k2 v1
  in tryNonce k2 v2
  where
    tryNonce k v =
      let v' = hmacSHA256 k v
          candidate = os2ip v'
      in if candidate >= 1 && candidate < curveN
         then candidate
         else let k' = hmacSHA256 k (v' <> BS.singleton 0x00)
                  v'' = hmacSHA256 k' v'
              in tryNonce k' v''

-- RFC 9381 Section 5.4.1.1: encode_to_curve (try_and_increment)
encodeToCurveTAI :: Point -> ByteString -> Maybe (Point, Int)
encodeToCurveTAI pkPoint alpha =
  let pkBytes = pointToBytes pkPoint
      prefix = BS.pack [suiteByte, 0x01] <> pkBytes
  in go prefix 0
  where
    go prefix ctr
      | ctr > 255 = Nothing
      | otherwise =
          let hashInput = prefix <> alpha <> BS.singleton (fromIntegral ctr) <> BS.singleton 0x00
              candidate = SHA256.hash hashInput
              compressed = BS.cons 0x02 candidate
          in case bytesToPoint compressed of
               Just pt -> Just (pt, ctr)
               Nothing -> go prefix (ctr + 1)

-- RFC 9381 Section 5.4.2.1: nonce generation via RFC 6979
vrfNonceGeneration :: ByteString -> Point -> Integer
vrfNonceGeneration sk hPoint =
  let hBytes = pointToBytes hPoint
      msgHash = SHA256.hash hBytes
  in nonceRFC6979 sk msgHash

-- RFC 9381 Section 5.4.3: challenge generation (5-point, includes Y)
challengeGeneration :: Point -> Point -> Point -> Point -> Point -> Integer
challengeGeneration y h gamma u v =
  let hashInput = BS.pack [suiteByte, 0x02]
                  <> pointToBytes y
                  <> pointToBytes h
                  <> pointToBytes gamma
                  <> pointToBytes u
                  <> pointToBytes v
                  <> BS.singleton 0x00
      cHash = SHA256.hash hashInput
  in os2ip (BS.take 16 cHash)

-- RFC 9381 Section 5.2: proof_to_hash (cofactor = 1 for secp256k1)
vrfProofToHash :: Point -> ByteString
vrfProofToHash gamma =
  let hashInput = BS.pack [suiteByte, 0x03]
                  <> pointToBytes gamma
                  <> BS.singleton 0x00
  in SHA256.hash hashInput

-- Decode an 81-byte proof into (Gamma, c, s)
decodeProof :: ByteString -> Maybe (Point, Integer, Integer)
decodeProof pi_
  | BS.length pi_ /= 81 = Nothing
  | otherwise =
      let gammaBytes = BS.take 33 pi_
          cBytes = BS.take 16 (BS.drop 33 pi_)
          sBytes = BS.drop 49 pi_
          c = os2ip cBytes
          s = os2ip sBytes
      in case bytesToPoint gammaBytes of
           Nothing -> Nothing
           Just gamma -> Just (gamma, c, s)

-- RFC 9381 Section 5.1: ECVRF_prove
prove :: ByteString -> ByteString -> Maybe ByteString
prove sk alpha
  | BS.length sk /= 32 = Nothing
  | otherwise =
      let x = os2ip sk
      in if x == 0 || x >= curveN
         then Nothing
         else
           let y = scalarMul x curveG
           in case encodeToCurveTAI y alpha of
                Nothing -> Nothing
                Just (h, _) ->
                  let gamma = scalarMul x h
                      k = vrfNonceGeneration sk h
                      u = scalarMul k curveG
                      v = scalarMul k h
                      c = challengeGeneration y h gamma u v
                      s = modN (k + c * x)
                      pi_ = pointToBytes gamma <> i2osp c 16 <> i2osp s 32
                  in Just pi_

-- RFC 9381 Section 5.3: ECVRF_verify
verify :: ByteString -> ByteString -> ByteString -> Maybe ByteString
verify pkBytes pi_ alpha = do
  y <- bytesToPoint pkBytes
  (gamma, c, s) <- decodeProof pi_
  if s >= curveN || c >= shiftL 1 128
    then Nothing
    else case encodeToCurveTAI y alpha of
           Nothing -> Nothing
           Just (h, _) ->
             let u = pointAdd (scalarMul s curveG) (scalarMul (curveN - c) y)
                 v = pointAdd (scalarMul s h) (scalarMul (curveN - c) gamma)
                 cPrime = challengeGeneration y h gamma u v
             in if c == cPrime
                then Just (vrfProofToHash gamma)
                else Nothing

-- Extract VRF output from proof
proofToHash :: ByteString -> Maybe ByteString
proofToHash pi_ = do
  (gamma, _, _) <- decodeProof pi_
  return (vrfProofToHash gamma)

-- Derive compressed public key from secret key
derivePublicKey :: ByteString -> Maybe ByteString
derivePublicKey sk
  | BS.length sk /= 32 = Nothing
  | otherwise =
      let x = os2ip sk
      in if x == 0 || x >= curveN
         then Nothing
         else Just (pointToBytes (scalarMul x curveG))
