package ibc.core.client.v1;

import static io.grpc.MethodDescriptor.generateFullMethodName;

/**
 * <pre>
 * Query provides defines the gRPC querier service
 * </pre>
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.39.0)",
    comments = "Source: ibc/core/client/v1/query.proto")
public final class QueryGrpc {

  private QueryGrpc() {}

  public static final String SERVICE_NAME = "ibc.core.client.v1.Query";

  // Static method descriptors that strictly reflect the proto.
  private static volatile io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryClientStateRequest,
      ibc.core.client.v1.QueryOuterClass.QueryClientStateResponse> getClientStateMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ClientState",
      requestType = ibc.core.client.v1.QueryOuterClass.QueryClientStateRequest.class,
      responseType = ibc.core.client.v1.QueryOuterClass.QueryClientStateResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryClientStateRequest,
      ibc.core.client.v1.QueryOuterClass.QueryClientStateResponse> getClientStateMethod() {
    io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryClientStateRequest, ibc.core.client.v1.QueryOuterClass.QueryClientStateResponse> getClientStateMethod;
    if ((getClientStateMethod = QueryGrpc.getClientStateMethod) == null) {
      synchronized (QueryGrpc.class) {
        if ((getClientStateMethod = QueryGrpc.getClientStateMethod) == null) {
          QueryGrpc.getClientStateMethod = getClientStateMethod =
              io.grpc.MethodDescriptor.<ibc.core.client.v1.QueryOuterClass.QueryClientStateRequest, ibc.core.client.v1.QueryOuterClass.QueryClientStateResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ClientState"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  ibc.core.client.v1.QueryOuterClass.QueryClientStateRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  ibc.core.client.v1.QueryOuterClass.QueryClientStateResponse.getDefaultInstance()))
              .setSchemaDescriptor(new QueryMethodDescriptorSupplier("ClientState"))
              .build();
        }
      }
    }
    return getClientStateMethod;
  }

  private static volatile io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryClientStatesRequest,
      ibc.core.client.v1.QueryOuterClass.QueryClientStatesResponse> getClientStatesMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ClientStates",
      requestType = ibc.core.client.v1.QueryOuterClass.QueryClientStatesRequest.class,
      responseType = ibc.core.client.v1.QueryOuterClass.QueryClientStatesResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryClientStatesRequest,
      ibc.core.client.v1.QueryOuterClass.QueryClientStatesResponse> getClientStatesMethod() {
    io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryClientStatesRequest, ibc.core.client.v1.QueryOuterClass.QueryClientStatesResponse> getClientStatesMethod;
    if ((getClientStatesMethod = QueryGrpc.getClientStatesMethod) == null) {
      synchronized (QueryGrpc.class) {
        if ((getClientStatesMethod = QueryGrpc.getClientStatesMethod) == null) {
          QueryGrpc.getClientStatesMethod = getClientStatesMethod =
              io.grpc.MethodDescriptor.<ibc.core.client.v1.QueryOuterClass.QueryClientStatesRequest, ibc.core.client.v1.QueryOuterClass.QueryClientStatesResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ClientStates"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  ibc.core.client.v1.QueryOuterClass.QueryClientStatesRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  ibc.core.client.v1.QueryOuterClass.QueryClientStatesResponse.getDefaultInstance()))
              .setSchemaDescriptor(new QueryMethodDescriptorSupplier("ClientStates"))
              .build();
        }
      }
    }
    return getClientStatesMethod;
  }

  private static volatile io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryConsensusStateRequest,
      ibc.core.client.v1.QueryOuterClass.QueryConsensusStateResponse> getConsensusStateMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ConsensusState",
      requestType = ibc.core.client.v1.QueryOuterClass.QueryConsensusStateRequest.class,
      responseType = ibc.core.client.v1.QueryOuterClass.QueryConsensusStateResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryConsensusStateRequest,
      ibc.core.client.v1.QueryOuterClass.QueryConsensusStateResponse> getConsensusStateMethod() {
    io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryConsensusStateRequest, ibc.core.client.v1.QueryOuterClass.QueryConsensusStateResponse> getConsensusStateMethod;
    if ((getConsensusStateMethod = QueryGrpc.getConsensusStateMethod) == null) {
      synchronized (QueryGrpc.class) {
        if ((getConsensusStateMethod = QueryGrpc.getConsensusStateMethod) == null) {
          QueryGrpc.getConsensusStateMethod = getConsensusStateMethod =
              io.grpc.MethodDescriptor.<ibc.core.client.v1.QueryOuterClass.QueryConsensusStateRequest, ibc.core.client.v1.QueryOuterClass.QueryConsensusStateResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ConsensusState"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  ibc.core.client.v1.QueryOuterClass.QueryConsensusStateRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  ibc.core.client.v1.QueryOuterClass.QueryConsensusStateResponse.getDefaultInstance()))
              .setSchemaDescriptor(new QueryMethodDescriptorSupplier("ConsensusState"))
              .build();
        }
      }
    }
    return getConsensusStateMethod;
  }

  private static volatile io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesRequest,
      ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesResponse> getConsensusStatesMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ConsensusStates",
      requestType = ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesRequest.class,
      responseType = ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesRequest,
      ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesResponse> getConsensusStatesMethod() {
    io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesRequest, ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesResponse> getConsensusStatesMethod;
    if ((getConsensusStatesMethod = QueryGrpc.getConsensusStatesMethod) == null) {
      synchronized (QueryGrpc.class) {
        if ((getConsensusStatesMethod = QueryGrpc.getConsensusStatesMethod) == null) {
          QueryGrpc.getConsensusStatesMethod = getConsensusStatesMethod =
              io.grpc.MethodDescriptor.<ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesRequest, ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ConsensusStates"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesResponse.getDefaultInstance()))
              .setSchemaDescriptor(new QueryMethodDescriptorSupplier("ConsensusStates"))
              .build();
        }
      }
    }
    return getConsensusStatesMethod;
  }

  private static volatile io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryClientParamsRequest,
      ibc.core.client.v1.QueryOuterClass.QueryClientParamsResponse> getClientParamsMethod;

  @io.grpc.stub.annotations.RpcMethod(
      fullMethodName = SERVICE_NAME + '/' + "ClientParams",
      requestType = ibc.core.client.v1.QueryOuterClass.QueryClientParamsRequest.class,
      responseType = ibc.core.client.v1.QueryOuterClass.QueryClientParamsResponse.class,
      methodType = io.grpc.MethodDescriptor.MethodType.UNARY)
  public static io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryClientParamsRequest,
      ibc.core.client.v1.QueryOuterClass.QueryClientParamsResponse> getClientParamsMethod() {
    io.grpc.MethodDescriptor<ibc.core.client.v1.QueryOuterClass.QueryClientParamsRequest, ibc.core.client.v1.QueryOuterClass.QueryClientParamsResponse> getClientParamsMethod;
    if ((getClientParamsMethod = QueryGrpc.getClientParamsMethod) == null) {
      synchronized (QueryGrpc.class) {
        if ((getClientParamsMethod = QueryGrpc.getClientParamsMethod) == null) {
          QueryGrpc.getClientParamsMethod = getClientParamsMethod =
              io.grpc.MethodDescriptor.<ibc.core.client.v1.QueryOuterClass.QueryClientParamsRequest, ibc.core.client.v1.QueryOuterClass.QueryClientParamsResponse>newBuilder()
              .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
              .setFullMethodName(generateFullMethodName(SERVICE_NAME, "ClientParams"))
              .setSampledToLocalTracing(true)
              .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  ibc.core.client.v1.QueryOuterClass.QueryClientParamsRequest.getDefaultInstance()))
              .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
                  ibc.core.client.v1.QueryOuterClass.QueryClientParamsResponse.getDefaultInstance()))
              .setSchemaDescriptor(new QueryMethodDescriptorSupplier("ClientParams"))
              .build();
        }
      }
    }
    return getClientParamsMethod;
  }

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static QueryStub newStub(io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<QueryStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<QueryStub>() {
        @java.lang.Override
        public QueryStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new QueryStub(channel, callOptions);
        }
      };
    return QueryStub.newStub(factory, channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static QueryBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<QueryBlockingStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<QueryBlockingStub>() {
        @java.lang.Override
        public QueryBlockingStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new QueryBlockingStub(channel, callOptions);
        }
      };
    return QueryBlockingStub.newStub(factory, channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static QueryFutureStub newFutureStub(
      io.grpc.Channel channel) {
    io.grpc.stub.AbstractStub.StubFactory<QueryFutureStub> factory =
      new io.grpc.stub.AbstractStub.StubFactory<QueryFutureStub>() {
        @java.lang.Override
        public QueryFutureStub newStub(io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
          return new QueryFutureStub(channel, callOptions);
        }
      };
    return QueryFutureStub.newStub(factory, channel);
  }

  /**
   * <pre>
   * Query provides defines the gRPC querier service
   * </pre>
   */
  public static abstract class QueryImplBase implements io.grpc.BindableService {

    /**
     * <pre>
     * ClientState queries an IBC light client.
     * </pre>
     */
    public void clientState(ibc.core.client.v1.QueryOuterClass.QueryClientStateRequest request,
        io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryClientStateResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getClientStateMethod(), responseObserver);
    }

    /**
     * <pre>
     * ClientStates queries all the IBC light clients of a chain.
     * </pre>
     */
    public void clientStates(ibc.core.client.v1.QueryOuterClass.QueryClientStatesRequest request,
        io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryClientStatesResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getClientStatesMethod(), responseObserver);
    }

    /**
     * <pre>
     * ConsensusState queries a consensus state associated with a client state at
     * a given height.
     * </pre>
     */
    public void consensusState(ibc.core.client.v1.QueryOuterClass.QueryConsensusStateRequest request,
        io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryConsensusStateResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getConsensusStateMethod(), responseObserver);
    }

    /**
     * <pre>
     * ConsensusStates queries all the consensus state associated with a given
     * client.
     * </pre>
     */
    public void consensusStates(ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesRequest request,
        io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getConsensusStatesMethod(), responseObserver);
    }

    /**
     * <pre>
     * ClientParams queries all parameters of the ibc client.
     * </pre>
     */
    public void clientParams(ibc.core.client.v1.QueryOuterClass.QueryClientParamsRequest request,
        io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryClientParamsResponse> responseObserver) {
      io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall(getClientParamsMethod(), responseObserver);
    }

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
          .addMethod(
            getClientStateMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                ibc.core.client.v1.QueryOuterClass.QueryClientStateRequest,
                ibc.core.client.v1.QueryOuterClass.QueryClientStateResponse>(
                  this, METHODID_CLIENT_STATE)))
          .addMethod(
            getClientStatesMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                ibc.core.client.v1.QueryOuterClass.QueryClientStatesRequest,
                ibc.core.client.v1.QueryOuterClass.QueryClientStatesResponse>(
                  this, METHODID_CLIENT_STATES)))
          .addMethod(
            getConsensusStateMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                ibc.core.client.v1.QueryOuterClass.QueryConsensusStateRequest,
                ibc.core.client.v1.QueryOuterClass.QueryConsensusStateResponse>(
                  this, METHODID_CONSENSUS_STATE)))
          .addMethod(
            getConsensusStatesMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesRequest,
                ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesResponse>(
                  this, METHODID_CONSENSUS_STATES)))
          .addMethod(
            getClientParamsMethod(),
            io.grpc.stub.ServerCalls.asyncUnaryCall(
              new MethodHandlers<
                ibc.core.client.v1.QueryOuterClass.QueryClientParamsRequest,
                ibc.core.client.v1.QueryOuterClass.QueryClientParamsResponse>(
                  this, METHODID_CLIENT_PARAMS)))
          .build();
    }
  }

  /**
   * <pre>
   * Query provides defines the gRPC querier service
   * </pre>
   */
  public static final class QueryStub extends io.grpc.stub.AbstractAsyncStub<QueryStub> {
    private QueryStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected QueryStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new QueryStub(channel, callOptions);
    }

    /**
     * <pre>
     * ClientState queries an IBC light client.
     * </pre>
     */
    public void clientState(ibc.core.client.v1.QueryOuterClass.QueryClientStateRequest request,
        io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryClientStateResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getClientStateMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * ClientStates queries all the IBC light clients of a chain.
     * </pre>
     */
    public void clientStates(ibc.core.client.v1.QueryOuterClass.QueryClientStatesRequest request,
        io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryClientStatesResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getClientStatesMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * ConsensusState queries a consensus state associated with a client state at
     * a given height.
     * </pre>
     */
    public void consensusState(ibc.core.client.v1.QueryOuterClass.QueryConsensusStateRequest request,
        io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryConsensusStateResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getConsensusStateMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * ConsensusStates queries all the consensus state associated with a given
     * client.
     * </pre>
     */
    public void consensusStates(ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesRequest request,
        io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getConsensusStatesMethod(), getCallOptions()), request, responseObserver);
    }

    /**
     * <pre>
     * ClientParams queries all parameters of the ibc client.
     * </pre>
     */
    public void clientParams(ibc.core.client.v1.QueryOuterClass.QueryClientParamsRequest request,
        io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryClientParamsResponse> responseObserver) {
      io.grpc.stub.ClientCalls.asyncUnaryCall(
          getChannel().newCall(getClientParamsMethod(), getCallOptions()), request, responseObserver);
    }
  }

  /**
   * <pre>
   * Query provides defines the gRPC querier service
   * </pre>
   */
  public static final class QueryBlockingStub extends io.grpc.stub.AbstractBlockingStub<QueryBlockingStub> {
    private QueryBlockingStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected QueryBlockingStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new QueryBlockingStub(channel, callOptions);
    }

    /**
     * <pre>
     * ClientState queries an IBC light client.
     * </pre>
     */
    public ibc.core.client.v1.QueryOuterClass.QueryClientStateResponse clientState(ibc.core.client.v1.QueryOuterClass.QueryClientStateRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getClientStateMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * ClientStates queries all the IBC light clients of a chain.
     * </pre>
     */
    public ibc.core.client.v1.QueryOuterClass.QueryClientStatesResponse clientStates(ibc.core.client.v1.QueryOuterClass.QueryClientStatesRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getClientStatesMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * ConsensusState queries a consensus state associated with a client state at
     * a given height.
     * </pre>
     */
    public ibc.core.client.v1.QueryOuterClass.QueryConsensusStateResponse consensusState(ibc.core.client.v1.QueryOuterClass.QueryConsensusStateRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getConsensusStateMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * ConsensusStates queries all the consensus state associated with a given
     * client.
     * </pre>
     */
    public ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesResponse consensusStates(ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getConsensusStatesMethod(), getCallOptions(), request);
    }

    /**
     * <pre>
     * ClientParams queries all parameters of the ibc client.
     * </pre>
     */
    public ibc.core.client.v1.QueryOuterClass.QueryClientParamsResponse clientParams(ibc.core.client.v1.QueryOuterClass.QueryClientParamsRequest request) {
      return io.grpc.stub.ClientCalls.blockingUnaryCall(
          getChannel(), getClientParamsMethod(), getCallOptions(), request);
    }
  }

  /**
   * <pre>
   * Query provides defines the gRPC querier service
   * </pre>
   */
  public static final class QueryFutureStub extends io.grpc.stub.AbstractFutureStub<QueryFutureStub> {
    private QueryFutureStub(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected QueryFutureStub build(
        io.grpc.Channel channel, io.grpc.CallOptions callOptions) {
      return new QueryFutureStub(channel, callOptions);
    }

    /**
     * <pre>
     * ClientState queries an IBC light client.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<ibc.core.client.v1.QueryOuterClass.QueryClientStateResponse> clientState(
        ibc.core.client.v1.QueryOuterClass.QueryClientStateRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getClientStateMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * ClientStates queries all the IBC light clients of a chain.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<ibc.core.client.v1.QueryOuterClass.QueryClientStatesResponse> clientStates(
        ibc.core.client.v1.QueryOuterClass.QueryClientStatesRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getClientStatesMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * ConsensusState queries a consensus state associated with a client state at
     * a given height.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<ibc.core.client.v1.QueryOuterClass.QueryConsensusStateResponse> consensusState(
        ibc.core.client.v1.QueryOuterClass.QueryConsensusStateRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getConsensusStateMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * ConsensusStates queries all the consensus state associated with a given
     * client.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesResponse> consensusStates(
        ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getConsensusStatesMethod(), getCallOptions()), request);
    }

    /**
     * <pre>
     * ClientParams queries all parameters of the ibc client.
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<ibc.core.client.v1.QueryOuterClass.QueryClientParamsResponse> clientParams(
        ibc.core.client.v1.QueryOuterClass.QueryClientParamsRequest request) {
      return io.grpc.stub.ClientCalls.futureUnaryCall(
          getChannel().newCall(getClientParamsMethod(), getCallOptions()), request);
    }
  }

  private static final int METHODID_CLIENT_STATE = 0;
  private static final int METHODID_CLIENT_STATES = 1;
  private static final int METHODID_CONSENSUS_STATE = 2;
  private static final int METHODID_CONSENSUS_STATES = 3;
  private static final int METHODID_CLIENT_PARAMS = 4;

  private static final class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final QueryImplBase serviceImpl;
    private final int methodId;

    MethodHandlers(QueryImplBase serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_CLIENT_STATE:
          serviceImpl.clientState((ibc.core.client.v1.QueryOuterClass.QueryClientStateRequest) request,
              (io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryClientStateResponse>) responseObserver);
          break;
        case METHODID_CLIENT_STATES:
          serviceImpl.clientStates((ibc.core.client.v1.QueryOuterClass.QueryClientStatesRequest) request,
              (io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryClientStatesResponse>) responseObserver);
          break;
        case METHODID_CONSENSUS_STATE:
          serviceImpl.consensusState((ibc.core.client.v1.QueryOuterClass.QueryConsensusStateRequest) request,
              (io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryConsensusStateResponse>) responseObserver);
          break;
        case METHODID_CONSENSUS_STATES:
          serviceImpl.consensusStates((ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesRequest) request,
              (io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryConsensusStatesResponse>) responseObserver);
          break;
        case METHODID_CLIENT_PARAMS:
          serviceImpl.clientParams((ibc.core.client.v1.QueryOuterClass.QueryClientParamsRequest) request,
              (io.grpc.stub.StreamObserver<ibc.core.client.v1.QueryOuterClass.QueryClientParamsResponse>) responseObserver);
          break;
        default:
          throw new AssertionError();
      }
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public io.grpc.stub.StreamObserver<Req> invoke(
        io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        default:
          throw new AssertionError();
      }
    }
  }

  private static abstract class QueryBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    QueryBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return ibc.core.client.v1.QueryOuterClass.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("Query");
    }
  }

  private static final class QueryFileDescriptorSupplier
      extends QueryBaseDescriptorSupplier {
    QueryFileDescriptorSupplier() {}
  }

  private static final class QueryMethodDescriptorSupplier
      extends QueryBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final String methodName;

    QueryMethodDescriptorSupplier(String methodName) {
      this.methodName = methodName;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.MethodDescriptor getMethodDescriptor() {
      return getServiceDescriptor().findMethodByName(methodName);
    }
  }

  private static volatile io.grpc.ServiceDescriptor serviceDescriptor;

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    io.grpc.ServiceDescriptor result = serviceDescriptor;
    if (result == null) {
      synchronized (QueryGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new QueryFileDescriptorSupplier())
              .addMethod(getClientStateMethod())
              .addMethod(getClientStatesMethod())
              .addMethod(getConsensusStateMethod())
              .addMethod(getConsensusStatesMethod())
              .addMethod(getClientParamsMethod())
              .build();
        }
      }
    }
    return result;
  }
}
