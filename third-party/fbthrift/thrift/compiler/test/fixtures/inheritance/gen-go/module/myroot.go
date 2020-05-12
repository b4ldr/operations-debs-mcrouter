// Autogenerated by Thrift Compiler (facebook)
// DO NOT EDIT UNLESS YOU ARE SURE THAT YOU KNOW WHAT YOU ARE DOING
// @generated

package module

import (
	"bytes"
	"context"
	"sync"
	"fmt"
	thrift "github.com/facebook/fbthrift/thrift/lib/go/thrift"
)

// (needed to ensure safety because of naive import list construction.)
var _ = thrift.ZERO
var _ = fmt.Printf
var _ = sync.Mutex{}
var _ = bytes.Equal
var _ = context.Background

type MyRoot interface {
  DoRoot() (err error)
}

type MyRootClientInterface interface {
  thrift.ClientInterface
  DoRoot() (err error)
}

type MyRootClient struct {
  MyRootClientInterface
  CC thrift.ClientConn
}

func(client *MyRootClient) Open() error {
  return client.CC.Open()
}

func(client *MyRootClient) Close() error {
  return client.CC.Close()
}

func(client *MyRootClient) IsOpen() bool {
  return client.CC.IsOpen()
}

func NewMyRootClientFactory(t thrift.Transport, f thrift.ProtocolFactory) *MyRootClient {
  return &MyRootClient{ CC: thrift.NewClientConn(t, f) }
}

func NewMyRootClient(t thrift.Transport, iprot thrift.Protocol, oprot thrift.Protocol) *MyRootClient {
  return &MyRootClient{ CC: thrift.NewClientConnWithProtocols(t, iprot, oprot) }
}

func (p *MyRootClient) DoRoot() (err error) {
  var args MyRootDoRootArgs
  err = p.CC.SendMsg("do_root", &args, thrift.CALL)
  if err != nil { return }
  return p.recvDoRoot()
}


func (p *MyRootClient) recvDoRoot() (err error) {
  var result MyRootDoRootResult
  return p.CC.RecvMsg("do_root", &result)
}


type MyRootThreadsafeClient struct {
  MyRootClientInterface
  CC thrift.ClientConn
  Mu sync.Mutex
}

func(client *MyRootThreadsafeClient) Open() error {
  client.Mu.Lock()
  defer client.Mu.Unlock()
  return client.CC.Open()
}

func(client *MyRootThreadsafeClient) Close() error {
  client.Mu.Lock()
  defer client.Mu.Unlock()
  return client.CC.Close()
}

func(client *MyRootThreadsafeClient) IsOpen() bool {
  client.Mu.Lock()
  defer client.Mu.Unlock()
  return client.CC.IsOpen()
}

func NewMyRootThreadsafeClientFactory(t thrift.Transport, f thrift.ProtocolFactory) *MyRootThreadsafeClient {
  return &MyRootThreadsafeClient{ CC: thrift.NewClientConn(t, f) }
}

func NewMyRootThreadsafeClient(t thrift.Transport, iprot thrift.Protocol, oprot thrift.Protocol) *MyRootThreadsafeClient {
  return &MyRootThreadsafeClient{ CC: thrift.NewClientConnWithProtocols(t, iprot, oprot) }
}

func (p *MyRootThreadsafeClient) DoRoot() (err error) {
  p.Mu.Lock()
  defer p.Mu.Unlock()
  var args MyRootDoRootArgs
  err = p.CC.SendMsg("do_root", &args, thrift.CALL)
  if err != nil { return }
  return p.recvDoRoot()
}


func (p *MyRootThreadsafeClient) recvDoRoot() (err error) {
  var result MyRootDoRootResult
  return p.CC.RecvMsg("do_root", &result)
}


type MyRootProcessor struct {
  processorMap map[string]thrift.ProcessorFunction
  handler MyRoot
}

func (p *MyRootProcessor) AddToProcessorMap(key string, processor thrift.ProcessorFunction) {
  p.processorMap[key] = processor
}

func (p *MyRootProcessor) GetProcessorFunction(key string) (processor thrift.ProcessorFunction, err error) {
  if processor, ok := p.processorMap[key]; ok {
    return processor, nil
  }
  return nil, nil // generic error message will be sent
}

func (p *MyRootProcessor) ProcessorMap() map[string]thrift.ProcessorFunction {
  return p.processorMap
}

func NewMyRootProcessor(handler MyRoot) *MyRootProcessor {
  self0 := &MyRootProcessor{handler:handler, processorMap:make(map[string]thrift.ProcessorFunction)}
  self0.processorMap["do_root"] = &myRootProcessorDoRoot{handler:handler}
  return self0
}

type myRootProcessorDoRoot struct {
  handler MyRoot
}

func (p *myRootProcessorDoRoot) Read(iprot thrift.Protocol) (thrift.Struct, thrift.Exception) {
  args := MyRootDoRootArgs{}
  if err := args.Read(iprot); err != nil {
    return nil, err
  }
  iprot.ReadMessageEnd()
  return &args, nil
}

func (p *myRootProcessorDoRoot) Write(seqId int32, result thrift.WritableStruct, oprot thrift.Protocol) (err thrift.Exception) {
  var err2 error
  messageType := thrift.REPLY
  switch result.(type) {
  case thrift.ApplicationException:
    messageType = thrift.EXCEPTION
  }
  if err2 = oprot.WriteMessageBegin("do_root", messageType, seqId); err2 != nil {
    err = err2
  }
  if err2 = result.Write(oprot); err == nil && err2 != nil {
    err = err2
  }
  if err2 = oprot.WriteMessageEnd(); err == nil && err2 != nil {
    err = err2
  }
  if err2 = oprot.Flush(); err == nil && err2 != nil {
    err = err2
  }
  return err
}

func (p *myRootProcessorDoRoot) Run(argStruct thrift.Struct) (thrift.WritableStruct, thrift.ApplicationException) {
  var result MyRootDoRootResult
  if err := p.handler.DoRoot(); err != nil {
    switch err.(type) {
    default:
      x := thrift.NewApplicationException(thrift.INTERNAL_ERROR, "Internal error processing do_root: " + err.Error())
      return x, x
    }
  }
  return &result, nil
}


// HELPER FUNCTIONS AND STRUCTURES

type MyRootDoRootArgs struct {
  thrift.IRequest
}

func NewMyRootDoRootArgs() *MyRootDoRootArgs {
  return &MyRootDoRootArgs{}
}

func (p *MyRootDoRootArgs) Read(iprot thrift.Protocol) error {
  if _, err := iprot.ReadStructBegin(); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T read error: ", p), err)
  }


  for {
    _, fieldTypeId, fieldId, err := iprot.ReadFieldBegin()
    if err != nil {
      return thrift.PrependError(fmt.Sprintf("%T field %d read error: ", p, fieldId), err)
    }
    if fieldTypeId == thrift.STOP { break; }
    if err := iprot.Skip(fieldTypeId); err != nil {
      return err
    }
    if err := iprot.ReadFieldEnd(); err != nil {
      return err
    }
  }
  if err := iprot.ReadStructEnd(); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T read struct end error: ", p), err)
  }
  return nil
}

func (p *MyRootDoRootArgs) Write(oprot thrift.Protocol) error {
  if err := oprot.WriteStructBegin("do_root_args"); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T write struct begin error: ", p), err) }
  if err := oprot.WriteFieldStop(); err != nil {
    return thrift.PrependError("write field stop error: ", err) }
  if err := oprot.WriteStructEnd(); err != nil {
    return thrift.PrependError("write struct stop error: ", err) }
  return nil
}

func (p *MyRootDoRootArgs) String() string {
  if p == nil {
    return "<nil>"
  }
  return fmt.Sprintf("MyRootDoRootArgs(%+v)", *p)
}

type MyRootDoRootResult struct {
  thrift.IResponse
}

func NewMyRootDoRootResult() *MyRootDoRootResult {
  return &MyRootDoRootResult{}
}

func (p *MyRootDoRootResult) Read(iprot thrift.Protocol) error {
  if _, err := iprot.ReadStructBegin(); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T read error: ", p), err)
  }


  for {
    _, fieldTypeId, fieldId, err := iprot.ReadFieldBegin()
    if err != nil {
      return thrift.PrependError(fmt.Sprintf("%T field %d read error: ", p, fieldId), err)
    }
    if fieldTypeId == thrift.STOP { break; }
    if err := iprot.Skip(fieldTypeId); err != nil {
      return err
    }
    if err := iprot.ReadFieldEnd(); err != nil {
      return err
    }
  }
  if err := iprot.ReadStructEnd(); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T read struct end error: ", p), err)
  }
  return nil
}

func (p *MyRootDoRootResult) Write(oprot thrift.Protocol) error {
  if err := oprot.WriteStructBegin("do_root_result"); err != nil {
    return thrift.PrependError(fmt.Sprintf("%T write struct begin error: ", p), err) }
  if err := oprot.WriteFieldStop(); err != nil {
    return thrift.PrependError("write field stop error: ", err) }
  if err := oprot.WriteStructEnd(); err != nil {
    return thrift.PrependError("write struct stop error: ", err) }
  return nil
}

func (p *MyRootDoRootResult) String() string {
  if p == nil {
    return "<nil>"
  }
  return fmt.Sprintf("MyRootDoRootResult(%+v)", *p)
}


