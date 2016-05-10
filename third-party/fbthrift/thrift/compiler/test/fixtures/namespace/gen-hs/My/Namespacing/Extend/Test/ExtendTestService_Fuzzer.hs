{-# LANGUAGE DeriveDataTypeable #-}
{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-missing-fields #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}
{-# OPTIONS_GHC -fno-warn-name-shadowing #-}
{-# OPTIONS_GHC -fno-warn-unused-imports #-}
{-# OPTIONS_GHC -fno-warn-unused-matches #-}

-----------------------------------------------------------------
-- Autogenerated by Thrift
--                                                             --
-- DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
--  @generated
-----------------------------------------------------------------

module My.Namespacing.Extend.Test.ExtendTestService_Fuzzer (main) where
import qualified My.Namespacing.Extend.Test.Extend_Types
import qualified My.Namespacing.Extend.Test.ExtendTestService_Client as Client
import qualified My.Namespacing.Test.Hsmodule_Types

import Prelude ( Bool(..), Enum, Float, IO, Double, String, Maybe(..),
                 Eq, Show, Ord,
                 concat, error, fromIntegral, fromEnum, length, map,
                 maybe, not, null, otherwise, return, show, toEnum,
                 enumFromTo, Bounded, minBound, maxBound, seq,
                 (.), (&&), (||), (==), (++), ($), (-), (>>=), (>>))

import qualified Control.Applicative as Applicative (ZipList(..))
import Control.Applicative ( (<*>) )
import qualified Control.DeepSeq as DeepSeq
import qualified Control.Exception as Exception
import qualified Control.Monad as Monad ( liftM, ap, when )
import qualified Data.ByteString.Lazy as BS
import Data.Functor ( (<$>) )
import qualified Data.Hashable as Hashable
import qualified Data.Int as Int
import qualified Data.Maybe as Maybe (catMaybes)
import qualified Data.Text.Lazy.Encoding as Encoding ( decodeUtf8, encodeUtf8 )
import qualified Data.Text.Lazy as LT
import qualified Data.Typeable as Typeable ( Typeable )
import qualified Data.HashMap.Strict as Map
import qualified Data.HashSet as Set
import qualified Data.Vector as Vector
import qualified Test.QuickCheck.Arbitrary as Arbitrary ( Arbitrary(..) )
import qualified Test.QuickCheck as QuickCheck ( elements )

import qualified Thrift
import qualified Thrift.Types as Types
import qualified Thrift.Serializable as Serializable
import qualified Thrift.Arbitraries as Arbitraries

import qualified My.Namespacing.Test.Hsmodule_Types as Hsmodule_Types

import Prelude ((>>), print)
import qualified Prelude as P
import Control.Monad (forM)
import qualified Data.List as L
import Data.Maybe (fromJust)
import qualified Data.Map as Map
import GHC.Int (Int64, Int32)
import Data.ByteString.Lazy (ByteString)
import System.Environment (getArgs)
import Test.QuickCheck (arbitrary)
import Test.QuickCheck.Gen (Gen(..))
import Thrift.FuzzerSupport


handleOptions :: ([Options -> Options], [String], [String]) -> Options
handleOptions (transformers, (serviceName:[]), []) | serviceName `P.elem` serviceNames
    = (P.foldl (P.flip ($)) defaultOptions transformers) { opt_service = serviceName } 
handleOptions (_, (serviceName:[]), []) | P.otherwise
    = P.error $ usage ++ "\nUnknown serviceName " ++ serviceName ++ ", should be one of " ++ (P.show serviceNames)
handleOptions (_, [], _) = P.error $ usage ++ "\nMissing mandatory serviceName to fuzz."
handleOptions (_, _a, []) = P.error $ usage ++ "\nToo many serviceNames, pick one."
handleOptions (_, _, e) = P.error $ usage ++ (P.show e)

main :: IO ()
main = do
    args <- getArgs
    let config = handleOptions (getOptions args)
    fuzz config

selectFuzzer :: Options -> (Options -> IO ())
selectFuzzer (Options _host _port service _timeout _framed _verbose) 
    = fromJust $ P.lookup service fuzzerFunctions

fuzz :: Options -> IO ()
fuzz config = (selectFuzzer config) config

-- Dynamic content

-- Configuration via command-line parsing

serviceNames :: [String]
serviceNames = ["check"]

fuzzerFunctions :: [(String, (Options -> IO ()))]
fuzzerFunctions = [("check", check_fuzzer)]

-- Random data generation
inf_Hsmodule_Types_HsFoo :: IO [Hsmodule_Types.HsFoo]
inf_Hsmodule_Types_HsFoo = infexamples (Arbitrary.arbitrary :: Gen Hsmodule_Types.HsFoo)

-- Fuzzers and exception handlers
check_fuzzer :: Options -> IO ()
check_fuzzer opts = do
  a1 <- Applicative.ZipList <$> inf_Hsmodule_Types_HsFoo
  _ <- forM (Applicative.getZipList a1) check_fuzzFunc
  return ()
  where
  check_fuzzFunc a1 = let param = (a1) in
    if opt_framed opts
    then withThriftDo opts (withFramedTransport opts) (check_fuzzOnce param) (check_exceptionHandler param)
    else withThriftDo opts (withHandle opts) (check_fuzzOnce param) (check_exceptionHandler param)

check_exceptionHandler :: (Show a1) => (a1) -> IO ()
check_exceptionHandler (a1) = do
  P.putStrLn $ "Got exception on data:"
  P.putStrLn $ "(" ++ show a1 ++ ")"
check_fuzzOnce (a1) client = Client.check client a1 >> return ()

