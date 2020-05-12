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

module MyService_Client(query,has_arg_docs) where
import Data.IORef
import Prelude ( Bool(..), Enum, Float, IO, Double, String, Maybe(..),
                 Eq, Show, Ord,
                 concat, error, fromIntegral, fromEnum, length, map,
                 maybe, not, null, otherwise, return, show, toEnum,
                 enumFromTo, Bounded, minBound, maxBound, seq, succ,
                 pred, enumFrom, enumFromThen, enumFromThenTo,
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
import Data.List
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

import qualified Module_Types as Module_Types
import qualified Includes_Types as Includes_Types


import qualified Service_Types
import qualified MyService
seqid = newIORef 0
query (ip,op) arg_s arg_i = do
  send_query op arg_s arg_i
  recv_query ip
send_query op arg_s arg_i = do
  seq <- seqid
  seqn <- readIORef seq
  Thrift.writeMessage op ("query", Types.M_CALL, seqn) $
    MyService.write_Query_args op (MyService.Query_args{MyService.query_args_s=arg_s,MyService.query_args_i=arg_i})
  Thrift.tFlush (Thrift.getTransport op)
recv_query ip =
  Thrift.readMessage ip $ \(fname,mtype,rseqid) -> do
    Monad.when (mtype == Types.M_EXCEPTION) $ Thrift.readAppExn ip >>= Exception.throw
    res <- MyService.read_Query_result ip
    return ()
has_arg_docs (ip,op) arg_s arg_i = do
  send_has_arg_docs op arg_s arg_i
  recv_has_arg_docs ip
send_has_arg_docs op arg_s arg_i = do
  seq <- seqid
  seqn <- readIORef seq
  Thrift.writeMessage op ("has_arg_docs", Types.M_CALL, seqn) $
    MyService.write_Has_arg_docs_args op (MyService.Has_arg_docs_args{MyService.has_arg_docs_args_s=arg_s,MyService.has_arg_docs_args_i=arg_i})
  Thrift.tFlush (Thrift.getTransport op)
recv_has_arg_docs ip =
  Thrift.readMessage ip $ \(fname,mtype,rseqid) -> do
    Monad.when (mtype == Types.M_EXCEPTION) $ Thrift.readAppExn ip >>= Exception.throw
    res <- MyService.read_Has_arg_docs_result ip
    return ()
