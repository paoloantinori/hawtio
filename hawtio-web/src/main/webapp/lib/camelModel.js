var _apacheCamelModel = {

  "definitions": {

    "expression": {
      "type": "object",
      "title": "Expression",
      "group": "language",
      "description": "A useful base class for an expression",
      "properties": {
        "expression": {
          "kind": "value",
          "type": "string"
        },
        "language": {
          "type": "string",
          "enum": [
            "constant",
            "el",
            "header",
            "javaScript",
            "jxpath",
            "method",
            "mvel",
            "ognl",
            "groovy",
            "property",
            "python",
            "php",
            "ref",
            "ruby",
            "simple",
            "spel",
            "sql",
            "tokenize",
            "xpath",
            "xquery"
          ],
          "description": "The camel expression language ot use",
          "tooltip": "Pick the expression language you want to use",
          "title": "Language"
        }
      }
    },
    "aggregate": {
      "type": "object",
      "title": "Aggregate",
      "group": "eip,routing",
      "description": "Aggregates many messages into a single message",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "correlationExpression": {
          "kind": "expression",
          "type": "expression",
          "description": "The expression used to calculate the correlation key to use for aggregation. The Exchange which has the same correlation key is aggregated together. If the correlation key could not be evaluated an Exception is thrown. You can disable this by using the ignoreBadCorrelationKeys option.",
          "title": "Correlation Expression",
          "optional": "false"
        },
        "completionPredicate": {
          "kind": "expression",
          "type": "expression",
          "description": "Sets the predicate used to determine if the aggregation is completed",
          "title": "Completion Predicate",
          "optional": "true"
        },
        "completionTimeout": {
          "kind": "expression",
          "type": "expression",
          "description": "Sets the completion timeout which would cause the aggregate to consider the group as complete and send out the aggregated exchange.",
          "title": "Completion Timeout",
          "optional": "true"
        },
        "completionSize": {
          "kind": "expression",
          "type": "expression",
          "description": "Sets the completion size which is the number of aggregated exchanges which would cause the aggregate to consider the group as complete and send out the aggregated exchange.",
          "title": "Completion Size",
          "optional": "true"
        },
        "optimisticLockRetryPolicy": {
          "kind": "element",
          "type": "object",
          "description": "Allows to configure retry settings when using optimistic locking.",
          "title": "Optimistic Lock Retry Policy",
          "optional": "true"
        },
        "parallelProcessing": {
          "kind": "attribute",
          "type": "bool",
          "description": "When aggregated are completed they are being send out of the aggregator. This option indicates whether or not Camel should use a thread pool with multiple threads for concurrency. If no custom thread pool has been specified then Camel creates a default pool with 10 concurrent threads.",
          "title": "Parallel Processing",
          "optional": "true"
        },
        "optimisticLocking": {
          "kind": "attribute",
          "type": "bool",
          "description": "Turns on using optimistic locking which requires the aggregationRepository being used is supporting this by implementing org.apache.camel.spi.OptimisticLockingAggregationRepository.",
          "title": "Optimistic Locking",
          "optional": "true"
        },
        "executorServiceRef": {
          "kind": "attribute",
          "type": "string",
          "description": "If using parallelProcessing you can specify a custom thread pool to be used. In fact also if you are not using parallelProcessing this custom thread pool is used to send out aggregated exchanges as well.",
          "title": "Executor Service Ref",
          "optional": "true"
        },
        "timeoutCheckerExecutorServiceRef": {
          "kind": "attribute",
          "type": "string",
          "description": "If using either of the completionTimeout completionTimeoutExpression or completionInterval options a background thread is created to check for the completion for every aggregator. Set this option to provide a custom thread pool to be used rather than creating a new thread for every aggregator.",
          "title": "Timeout Checker Executor Service Ref",
          "optional": "true"
        },
        "aggregationRepositoryRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the custom aggregate repository to use Will by default use org.apache.camel.processor.aggregate.MemoryAggregationRepository",
          "title": "Aggregation Repository Ref",
          "optional": "true"
        },
        "strategyRef": {
          "kind": "attribute",
          "type": "string",
          "description": "A reference to lookup the AggregationStrategy in the Registry. Configuring an AggregationStrategy is required and is used to merge the incoming Exchange with the existing already merged exchanges. At first call the oldExchange parameter is null. On subsequent invocations the oldExchange contains the merged exchanges and newExchange is of course the new incoming Exchange.",
          "title": "Strategy Ref",
          "optional": "true"
        },
        "strategyMethodName": {
          "kind": "attribute",
          "type": "string",
          "description": "This option can be used to explicit declare the method name to use when using POJOs as the AggregationStrategy.",
          "title": "Strategy Method Name",
          "optional": "true"
        },
        "strategyMethodAllowNull": {
          "kind": "attribute",
          "type": "bool",
          "description": "If this option is false then the aggregate method is not used for the very first aggregation. If this option is true then null values is used as the oldExchange (at the very first aggregation) when using POJOs as the AggregationStrategy.",
          "title": "Strategy Method Allow Null",
          "optional": "true"
        },
        "completionInterval": {
          "kind": "attribute",
          "type": "integer",
          "description": "Sets the completion interval which would cause the aggregate to consider the group as complete and send out the aggregated exchange.",
          "title": "Completion Interval",
          "optional": "true"
        },
        "completionFromBatchConsumer": {
          "kind": "attribute",
          "type": "bool",
          "description": "Enables the batch completion mode where we aggregate from a org.apache.camel.BatchConsumer and aggregate the total number of exchanges the org.apache.camel.BatchConsumer has reported as total by checking the exchange property link org.apache.camel.ExchangeBATCH_COMPLETE when its complete.",
          "title": "Completion From Batch Consumer",
          "optional": "true"
        },
        "groupExchanges": {
          "kind": "attribute",
          "type": "bool",
          "description": "Enables grouped exchanges so the aggregator will group all aggregated exchanges into a single combined Exchange holding all the aggregated exchanges in a java.util.List.",
          "title": "Group Exchanges",
          "optional": "true"
        },
        "eagerCheckCompletion": {
          "kind": "attribute",
          "type": "bool",
          "description": "Use eager completion checking which means that the completionPredicate will use the incoming Exchange. At opposed to without eager completion checking the completionPredicate will use the aggregated Exchange.",
          "title": "Eager Check Completion",
          "optional": "true"
        },
        "ignoreInvalidCorrelationKeys": {
          "kind": "attribute",
          "type": "bool",
          "description": "If a correlation key cannot be successfully evaluated it will be ignored by logging a DEBUG and then just ignore the incoming Exchange.",
          "title": "Ignore Invalid Correlation Keys",
          "optional": "true"
        },
        "closeCorrelationKeyOnCompletion": {
          "kind": "attribute",
          "type": "number",
          "description": "Closes a correlation key when its complete. Any late received exchanges which has a correlation key that has been closed it will be defined and a org.apache.camel.processor.aggregate.ClosedCorrelationKeyException is thrown.",
          "title": "Close Correlation Key On Completion",
          "optional": "true"
        },
        "discardOnCompletionTimeout": {
          "kind": "attribute",
          "type": "bool",
          "description": "Discards the aggregated message on completion timeout. This means on timeout the aggregated message is dropped and not sent out of the aggregator.",
          "title": "Discard On Completion Timeout",
          "optional": "true"
        },
        "forceCompletionOnStop": {
          "kind": "attribute",
          "type": "bool",
          "description": "Indicates to complete all current aggregated exchanges when the context is stopped",
          "title": "Force Completion On Stop",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "aop": {
      "type": "object",
      "title": "Aop",
      "group": "configuration",
      "description": "Does processing before and/or after the route is completed",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "beforeUri": {
          "kind": "attribute",
          "type": "string",
          "description": "Endpoint to call in AOP before.",
          "title": "Before Uri",
          "optional": "true"
        },
        "afterUri": {
          "kind": "attribute",
          "type": "string",
          "description": "Endpoint to call in AOP after. The difference between after and afterFinally is that afterFinally is invoked from a finally block so it will always be invoked no matter what eg also in case of an exception occur.",
          "title": "After Uri",
          "optional": "true"
        },
        "afterFinallyUri": {
          "kind": "attribute",
          "type": "string",
          "description": "Endpoint to call in AOP after finally. The difference between after and afterFinally is that afterFinally is invoked from a finally block so it will always be invoked no matter what eg also in case of an exception occur.",
          "title": "After Finally Uri",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "batch-config": {
      "type": "object",
      "title": "Batch-config",
      "group": "configuration,resequence",
      "description": "Configures batch-processing resequence eip.",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "batchSize": {
          "kind": "attribute",
          "type": "number",
          "description": "Sets the size of the batch to be re-ordered. The default size is 100.",
          "title": "Batch Size",
          "optional": "true"
        },
        "batchTimeout": {
          "kind": "attribute",
          "type": "integer",
          "description": "Sets the timeout for collecting elements to be re-ordered. The default timeout is 1000 msec.",
          "title": "Batch Timeout",
          "optional": "true"
        },
        "allowDuplicates": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to allow duplicates.",
          "title": "Allow Duplicates",
          "optional": "true"
        },
        "reverse": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to reverse the ordering.",
          "title": "Reverse",
          "optional": "true"
        },
        "ignoreInvalidExchanges": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to ignore invalid exchanges",
          "title": "Ignore Invalid Exchanges",
          "optional": "true"
        }
      }
    },
    "bean": {
      "type": "object",
      "title": "Bean",
      "group": "eip,endpoint",
      "description": "Calls a java bean",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets a reference to a bean to use",
          "title": "Ref",
          "optional": "true"
        },
        "method": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the method name on the bean to use",
          "title": "Method",
          "optional": "true"
        },
        "beanType": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the Class of the bean",
          "title": "Bean Type",
          "optional": "true"
        },
        "cache": {
          "kind": "attribute",
          "type": "bool",
          "description": "Caches the bean lookup to avoid lookup up bean on every usage.",
          "title": "Cache",
          "optional": "true"
        },
        "multiParameterArray": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether the message body is an array type.",
          "title": "Multi Parameter Array",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "choice": {
      "type": "object",
      "title": "Choice",
      "group": "eip,routing",
      "description": "Routes messages based on a series of predicates",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "otherwise": {
          "kind": "element",
          "type": "object",
          "description": "Sets the otherwise node",
          "title": "Otherwise",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "circuitBreaker": {
      "type": "object",
      "title": "Circuit Breaker",
      "group": "configuration,loadbalance",
      "description": "Circuit break load balancer",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "exception": {
          "kind": "element",
          "type": "array",
          "description": "A list of class names for specific exceptions to monitor. If no exceptions is configured then all exceptions is monitored",
          "title": "Exception",
          "optional": "true"
        },
        "halfOpenAfter": {
          "kind": "attribute",
          "type": "integer",
          "description": "The timeout in millis to use as threshold to move state from closed to half-open or open state",
          "title": "Half Open After",
          "optional": "true"
        },
        "threshold": {
          "kind": "attribute",
          "type": "number",
          "description": "Number of previous failed messages to use as threshold to move state from closed to half-open or open state",
          "title": "Threshold",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "contextScan": {
      "type": "object",
      "title": "Context Scan",
      "group": "configuration",
      "description": "Scans for Java org.apache.camel.builder.RouteBuilder instances in the context org.apache.camel.spi.Registry.",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "excludes": {
          "kind": "element",
          "type": "array",
          "description": "Exclude finding route builder from these java package names.",
          "title": "Excludes",
          "optional": "true"
        },
        "includes": {
          "kind": "element",
          "type": "array",
          "description": "Include finding route builder from these java package names.",
          "title": "Includes",
          "optional": "true"
        }
      }
    },
    "convertBodyTo": {
      "type": "object",
      "title": "Convert Body To",
      "group": "eip,transformation",
      "description": "Converts the message body to another type",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "type": {
          "kind": "attribute",
          "type": "string",
          "description": "The java type to convert to",
          "title": "Type",
          "optional": "false"
        },
        "charset": {
          "kind": "attribute",
          "type": "string",
          "description": "To use a specific charset when converting",
          "title": "Charset",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "customLoadBalancer": {
      "type": "object",
      "title": "Custom Load Balancer",
      "group": "configuration,loadbalance",
      "description": "Custom load balancer",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to the custom load balancer to lookup from the registry",
          "title": "Ref",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "delay": {
      "type": "object",
      "title": "Delay",
      "group": "eip,routing",
      "description": "Delays processing for a specified length of time",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "executorServiceRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to a custom Thread Pool if asyncDelay has been enabled.",
          "title": "Executor Service Ref",
          "optional": "true"
        },
        "asyncDelayed": {
          "kind": "attribute",
          "type": "bool",
          "description": "Enables asynchronous delay which means the thread will noy block while delaying.",
          "title": "Async Delayed",
          "optional": "true"
        },
        "callerRunsWhenRejected": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the caller should run the task when it was rejected by the thread pool. Is by default true",
          "title": "Caller Runs When Rejected",
          "optional": "true"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression to define how long time to wait (in millis)",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "description": {
      "type": "object",
      "title": "Description",
      "group": "configuration",
      "description": "To provide comments about the node.",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "lang": {
          "kind": "attribute",
          "type": "string",
          "description": "Language such as en for english.",
          "title": "Lang",
          "optional": "true"
        },
        "layoutX": {
          "kind": "attribute",
          "type": "number",
          "description": "Layout position X",
          "title": "Layout X",
          "optional": "true"
        },
        "layoutY": {
          "kind": "attribute",
          "type": "number",
          "description": "Layout position Y",
          "title": "Layout Y",
          "optional": "true"
        },
        "layoutWidth": {
          "kind": "attribute",
          "type": "number",
          "description": "Layout width",
          "title": "Layout Width",
          "optional": "true"
        },
        "layoutHeight": {
          "kind": "attribute",
          "type": "number",
          "description": "Layout height",
          "title": "Layout Height",
          "optional": "true"
        },
        "text": {
          "kind": "value",
          "type": "string",
          "description": "The description as human readable text",
          "title": "Text",
          "optional": "false"
        }
      }
    },
    "doCatch": {
      "type": "object",
      "title": "Do Catch",
      "group": "error",
      "description": "Catches exceptions as part of a try catch finally block",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "exception": {
          "kind": "element",
          "type": "array",
          "description": "The exception(s) to catch.",
          "title": "Exception",
          "optional": "true"
        },
        "onWhen": {
          "kind": "element",
          "type": "object",
          "description": "Sets an additional predicate that should be true before the onCatch is triggered. To be used for fine grained controlling whether a thrown exception should be intercepted by this exception type or not.",
          "title": "On When",
          "optional": "true"
        },
        "handled": {
          "kind": "expression",
          "type": "expression",
          "description": "Sets whether the exchange should be marked as handled or not.",
          "title": "Handled",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "doFinally": {
      "type": "object",
      "title": "Do Finally",
      "group": "error",
      "description": "Path traversed when a try catch finally block exits",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "doTry": {
      "type": "object",
      "title": "Do Try",
      "group": "error",
      "description": "Marks the beginning of a try catch finally block",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "dynamicRouter": {
      "type": "object",
      "title": "Dynamic Router",
      "group": "eip,endpoint,routing",
      "description": "Routes messages based on dynamic rules",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "uriDelimiter": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the uri delimiter to use",
          "title": "Uri Delimiter",
          "optional": "true"
        },
        "ignoreInvalidEndpoints": {
          "kind": "attribute",
          "type": "bool",
          "description": "Ignore the invalidate endpoint exception when try to create a producer with that endpoint",
          "title": "Ignore Invalid Endpoints",
          "optional": "true"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression to call that returns the endpoint(s) to route to in the dynamic routing. Important: The expression will be called in a while loop fashion until the expression returns null which means the dynamic router is finished.",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "enrich": {
      "type": "object",
      "title": "Enrich",
      "group": "eip,transformation",
      "description": "Enriches a message with data from a secondary resource",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "The endpoint uri for the external service to enrich from. You must use either uri or ref.",
          "title": "Uri",
          "optional": "true"
        },
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to the endpoint for the external service to enrich from. You must use either uri or ref.",
          "title": "Ref",
          "optional": "true"
        },
        "strategyRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to an AggregationStrategy to be used to merge the reply from the external service into a single outgoing message. By default Camel will use the reply from the external service as outgoing message.",
          "title": "Strategy Ref",
          "optional": "true"
        },
        "strategyMethodName": {
          "kind": "attribute",
          "type": "string",
          "description": "This option can be used to explicit declare the method name to use when using POJOs as the AggregationStrategy.",
          "title": "Strategy Method Name",
          "optional": "true"
        },
        "strategyMethodAllowNull": {
          "kind": "attribute",
          "type": "bool",
          "description": "If this option is false then the aggregate method is not used if there was no data to enrich. If this option is true then null values is used as the oldExchange (when no data to enrich) when using POJOs as the AggregationStrategy.",
          "title": "Strategy Method Allow Null",
          "optional": "true"
        },
        "aggregateOnException": {
          "kind": "attribute",
          "type": "bool",
          "description": "If this option is false then the aggregate method is not used if there was an exception thrown while trying to retrieve the data to enrich from the resource. Setting this option to true allows end users to control what to do if there was an exception in the aggregate method. For example to suppress the exception or set a custom message body etc.",
          "title": "Aggregate On Exception",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "failover": {
      "type": "object",
      "title": "Failover",
      "group": "configuration,loadbalance",
      "description": "Failover load balancer",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "exception": {
          "kind": "element",
          "type": "array",
          "description": "A list of class names for specific exceptions to monitor. If no exceptions is configured then all exceptions is monitored",
          "title": "Exception",
          "optional": "true"
        },
        "roundRobin": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the failover load balancer should operate in round robin mode or not. If not then it will always start from the first endpoint when a new message is to be processed. In other words it restart from the top for every message. If round robin is enabled then it keeps state and will continue with the next endpoint in a round robin fashion. When using round robin it will not stick to last known good endpoint it will always pick the next endpoint to use.",
          "title": "Round Robin",
          "optional": "true"
        },
        "maximumFailoverAttempts": {
          "kind": "attribute",
          "type": "number",
          "description": "A value to indicate after X failover attempts we should exhaust (give up). Use -1 to indicate never give up and continuously try to failover. Use 0 to never failover. And use e.g. 3 to failover at most 3 times before giving up. his option can be used whether or not roundRobin is enabled or not.",
          "title": "Maximum Failover Attempts",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "filter": {
      "type": "object",
      "title": "Filter",
      "group": "eip,routing",
      "description": "Filter out messages based using a predicate",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression to determine if the message should be filtered or not. If the expression returns an empty value or false then the message is filtered (dropped) otherwise the message is continued being routed.",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "from": {
      "type": "object",
      "title": "From",
      "group": "eip,endpoint,routing",
      "description": "Act as a message source as input to a route",
      "acceptInput": "false",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the URI of the endpoint to use",
          "title": "Uri",
          "optional": "true"
        },
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the name of the endpoint within the registry (such as the Spring ApplicationContext or JNDI) to use",
          "title": "Ref",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "idempotentConsumer": {
      "type": "object",
      "title": "Idempotent Consumer",
      "group": "eip,routing",
      "description": "Filters out duplicate messages",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "messageIdRepositoryRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the reference name of the message id repository",
          "title": "Message Id Repository Ref",
          "optional": "false"
        },
        "eager": {
          "kind": "attribute",
          "type": "bool",
          "description": "Sets whether to eagerly add the key to the idempotent repository or wait until the exchange is complete. Eager is default enabled.",
          "title": "Eager",
          "optional": "true"
        },
        "skipDuplicate": {
          "kind": "attribute",
          "type": "bool",
          "description": "Sets whether to skip duplicates or not. The default behavior is to skip duplicates. A duplicate message would have the Exchange property link org.apache.camel.ExchangeDUPLICATE_MESSAGE set to a link BooleanTRUE value. A none duplicate message will not have this property set.",
          "title": "Skip Duplicate",
          "optional": "true"
        },
        "removeOnFailure": {
          "kind": "attribute",
          "type": "bool",
          "description": "Sets whether to remove or keep the key on failure. The default behavior is to remove the key on failure.",
          "title": "Remove On Failure",
          "optional": "true"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression used to calculate the correlation key to use for duplicate check. The Exchange which has the same correlation key is regarded as a duplicate and will be rejected.",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "inOnly": {
      "type": "object",
      "title": "In Only",
      "group": "eip,endpoint,routing",
      "description": "Marks the exchange pattern for the route to one way",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the uri of the endpoint to send to.",
          "title": "Uri",
          "optional": "true"
        },
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the reference of the endpoint to send to.",
          "title": "Ref",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "inOut": {
      "type": "object",
      "title": "In Out",
      "group": "eip,endpoint,routing",
      "description": "Marks the exchange pattern for the route to request/reply",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the uri of the endpoint to send to.",
          "title": "Uri",
          "optional": "true"
        },
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the reference of the endpoint to send to.",
          "title": "Ref",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "intercept": {
      "type": "object",
      "title": "Intercept",
      "group": "configuration",
      "description": "Intercepts a message at each step in the route",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "interceptFrom": {
      "type": "object",
      "title": "Intercept From",
      "group": "configuration",
      "description": "Intercepts incoming messages",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Intercept incoming messages from the uri or uri pattern. If this option is not configured then all incoming messages is intercepted.",
          "title": "Uri",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "interceptSendToEndpoint": {
      "type": "object",
      "title": "Intercept Send To Endpoint",
      "group": "configuration",
      "description": "Intercepts messages being sent to an endpoint",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Intercept sending to the uri or uri pattern.",
          "title": "Uri",
          "optional": "false"
        },
        "skipSendToOriginalEndpoint": {
          "kind": "attribute",
          "type": "bool",
          "description": "If set to true then the message is not sent to the original endpoint. By default (false) the message is both intercepted and then sent to the original endpoint.",
          "title": "Skip Send To Original Endpoint",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "loadBalance": {
      "type": "object",
      "title": "Load Balance",
      "group": "eip,routing",
      "description": "Balances message processing among a number of nodes",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "To use a custom load balancer. This option is deprecated use the custom load balancer type instead.",
          "title": "Ref",
          "optional": "true"
        },
        "loadBalancerType": {
          "kind": "element",
          "type": "object",
          "description": "The load balancer to be used",
          "title": "Load Balancer Type",
          "optional": "false"
        },
        "inheritErrorHandler": {
          "kind": "attribute",
          "type": "bool",
          "description": "Sets whether or not to inherit the configured error handler. The default value is true. You can use this to disable using the inherited error handler for a given DSL such as a load balancer where you want to use a custom error handler strategy.",
          "title": "Inherit Error Handler",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "log": {
      "type": "object",
      "title": "Log",
      "group": "configuration",
      "description": "Logs the defined message to the logger",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "message": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the log message (uses simple language)",
          "title": "Message",
          "optional": "false"
        },
        "loggingLevel": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the logging level. The default value is INFO",
          "title": "Logging Level",
          "optional": "true"
        },
        "logName": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the name of the logger",
          "title": "Log Name",
          "optional": "true"
        },
        "marker": {
          "kind": "attribute",
          "type": "string",
          "description": "To use slf4j marker",
          "title": "Marker",
          "optional": "true"
        },
        "loggerRef": {
          "kind": "attribute",
          "type": "string",
          "description": "To refer to a custom logger instance to lookup from ther registry.",
          "title": "Logger Ref",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "loop": {
      "type": "object",
      "title": "Loop",
      "group": "eip,routing",
      "description": "Processes a message multiple times",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "copy": {
          "kind": "attribute",
          "type": "bool",
          "description": "If the copy attribute is true a copy of the input Exchange is used for each iteration. That means each iteration will start from a copy of the same message. By default loop will loop the same exchange all over so each iteration may have different message content.",
          "title": "Copy",
          "optional": "true"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression to define how many times we should loop. Notice the expression is only evaluated once and should return a number as how many times to loop. A value of zero or negative means no looping. The loop is like a for-loop fashion if you want a while loop then the dynamic router may be a better choice.",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "marshal": {
      "type": "object",
      "title": "Marshal",
      "group": "eip,transformation",
      "description": "Marshals data into a specified format for transmission over a transport or component",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "dataFormatType": {
          "kind": "element",
          "type": "object",
          "description": "The data format to be used",
          "title": "Data Format Type",
          "optional": "false"
        },
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "To refer to a custom data format to use as marshaller",
          "title": "Ref",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "multicast": {
      "type": "object",
      "title": "Multicast",
      "group": "eip,routing",
      "description": "Routes the same message to multiple paths either sequentially or in parallel.",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "parallelProcessing": {
          "kind": "attribute",
          "type": "bool",
          "description": "If enabled then sending messages to the multicasts occurs concurrently. Note the caller thread will still wait until all messages has been fully processed before it continues. Its only the sending and processing the replies from the multicasts which happens concurrently.",
          "title": "Parallel Processing",
          "optional": "true"
        },
        "strategyRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to an AggregationStrategy to be used to assemble the replies from the multicasts into a single outgoing message from the Multicast. By default Camel will use the last reply as the outgoing message. You can also use a POJO as the AggregationStrategy",
          "title": "Strategy Ref",
          "optional": "true"
        },
        "strategyMethodName": {
          "kind": "attribute",
          "type": "string",
          "description": "This option can be used to explicit declare the method name to use when using POJOs as the AggregationStrategy.",
          "title": "Strategy Method Name",
          "optional": "true"
        },
        "strategyMethodAllowNull": {
          "kind": "attribute",
          "type": "bool",
          "description": "If this option is false then the aggregate method is not used if there was no data to enrich. If this option is true then null values is used as the oldExchange (when no data to enrich) when using POJOs as the AggregationStrategy",
          "title": "Strategy Method Allow Null",
          "optional": "true"
        },
        "executorServiceRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to a custom Thread Pool to be used for parallel processing. Notice if you set this option then parallel processing is automatic implied and you do not have to enable that option as well.",
          "title": "Executor Service Ref",
          "optional": "true"
        },
        "streaming": {
          "kind": "attribute",
          "type": "bool",
          "description": "If enabled then Camel will process replies out-of-order eg in the order they come back. If disabled Camel will process replies in the same order as defined by the multicast.",
          "title": "Streaming",
          "optional": "true"
        },
        "stopOnException": {
          "kind": "attribute",
          "type": "bool",
          "description": "Will now stop further processing if an exception or failure occurred during processing of an org.apache.camel.Exchange and the caused exception will be thrown. Will also stop if processing the exchange failed (has a fault message) or an exception was thrown and handled by the error handler (such as using onException). In all situations the multicast will stop further processing. This is the same behavior as in pipeline which is used by the routing engine. The default behavior is to not stop but continue processing till the end",
          "title": "Stop On Exception",
          "optional": "true"
        },
        "timeout": {
          "kind": "attribute",
          "type": "integer",
          "description": "Sets a total timeout specified in millis when using parallel processing. If the Multicast hasn't been able to send and process all replies within the given timeframe then the timeout triggers and the Multicast breaks out and continues. Notice if you provide a TimeoutAwareAggregationStrategy then the timeout method is invoked before breaking out. If the timeout is reached with running tasks still remaining certain tasks for which it is difficult for Camel to shut down in a graceful manner may continue to run. So use this option with a bit of care.",
          "title": "Timeout",
          "optional": "true"
        },
        "onPrepareRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Uses the Processor when preparing the org.apache.camel.Exchange to be send. This can be used to deep-clone messages that should be send or any custom logic needed before the exchange is send.",
          "title": "On Prepare Ref",
          "optional": "true"
        },
        "shareUnitOfWork": {
          "kind": "attribute",
          "type": "bool",
          "description": "Shares the org.apache.camel.spi.UnitOfWork with the parent and each of the sub messages. Multicast will by default not share unit of work between the parent exchange and each multicasted exchange. This means each sub exchange has its own individual unit of work.",
          "title": "Share Unit Of Work",
          "optional": "true"
        },
        "parallelAggregate": {
          "kind": "attribute",
          "type": "bool",
          "description": "If enabled then the aggregate method on AggregationStrategy can be called concurrently. Notice that this would require the implementation of AggregationStrategy to be implemented as thread-safe. By default this is false meaning that Camel synchronizes the call to the aggregate method. Though in some use-cases this can be used to archive higher performance when the AggregationStrategy is implemented as thread-safe.",
          "title": "Parallel Aggregate",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "onCompletion": {
      "type": "object",
      "title": "On Completion",
      "group": "configuration",
      "description": "Route to be executed when normal route processing completes",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "mode": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the on completion mode. The default value is AfterConsumer",
          "title": "Mode",
          "optional": "true"
        },
        "onCompleteOnly": {
          "kind": "attribute",
          "type": "bool",
          "description": "Will only synchronize when the org.apache.camel.Exchange completed successfully (no errors).",
          "title": "On Complete Only",
          "optional": "true"
        },
        "onFailureOnly": {
          "kind": "attribute",
          "type": "bool",
          "description": "Will only synchronize when the org.apache.camel.Exchange ended with failure (exception or FAULT message).",
          "title": "On Failure Only",
          "optional": "true"
        },
        "onWhen": {
          "kind": "element",
          "type": "object",
          "description": "Sets an additional predicate that should be true before the onCompletion is triggered. To be used for fine grained controlling whether a completion callback should be invoked or not",
          "title": "On When",
          "optional": "true"
        },
        "parallelProcessing": {
          "kind": "attribute",
          "type": "bool",
          "description": "If enabled then the on completion process will run asynchronously by a separate thread from a thread pool. By default this is false meaning the on completion process will run synchronously using the same caller thread as from the route.",
          "title": "Parallel Processing",
          "optional": "true"
        },
        "executorServiceRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to a custom Thread Pool to be used for parallel processing. Notice if you set this option then parallel processing is automatic implied and you do not have to enable that option as well.",
          "title": "Executor Service Ref",
          "optional": "true"
        },
        "useOriginalMessage": {
          "kind": "attribute",
          "type": "bool",
          "description": "Will use the original input body when an org.apache.camel.Exchange for this on completion. By default this feature is off.",
          "title": "Use Original Message",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "onException": {
      "type": "object",
      "title": "On Exception",
      "group": "error",
      "description": "Route to be executed when an exception is thrown",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "exception": {
          "kind": "element",
          "type": "array",
          "description": "A set of exceptions to react upon.",
          "title": "Exception",
          "optional": "false"
        },
        "onWhen": {
          "kind": "element",
          "type": "object",
          "description": "Sets an additional predicate that should be true before the onException is triggered. To be used for fine grained controlling whether a thrown exception should be intercepted by this exception type or not.",
          "title": "On When",
          "optional": "true"
        },
        "retryWhile": {
          "kind": "expression",
          "type": "expression",
          "description": "Sets the retry while predicate. Will continue retrying until predicate returns false.",
          "title": "Retry While",
          "optional": "true"
        },
        "redeliveryPolicy": {
          "kind": "element",
          "type": "object",
          "description": "Set the RedeliveryPolicy to be used.",
          "title": "Redelivery Policy",
          "optional": "true"
        },
        "redeliveryPolicyRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets a reference to a RedeliveryPolicy to lookup in the org.apache.camel.spi.Registry to be used.",
          "title": "Redelivery Policy Ref",
          "optional": "true"
        },
        "handled": {
          "kind": "expression",
          "type": "expression",
          "description": "Sets whether the exchange should be marked as handled or not.",
          "title": "Handled",
          "optional": "true"
        },
        "continued": {
          "kind": "expression",
          "type": "expression",
          "description": "Sets whether the exchange should handle and continue routing from the point of failure. If this option is enabled then its considered handled as well.",
          "title": "Continued",
          "optional": "true"
        },
        "onRedeliveryRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets a reference to a processor that should be processed before a redelivery attempt. Can be used to change the org.apache.camel.Exchange before its being redelivered.",
          "title": "On Redelivery Ref",
          "optional": "true"
        },
        "useOriginalMessage": {
          "kind": "attribute",
          "type": "bool",
          "description": "Will use the original input message when an org.apache.camel.Exchange is moved to the dead letter queue. Notice: this only applies when all redeliveries attempt have failed and the org.apache.camel.Exchange is doomed for failure. Instead of using the current inprogress org.apache.camel.Exchange IN body we use the original IN body instead. This allows you to store the original input in the dead letter queue instead of the inprogress snapshot of the IN body. For instance if you route transform the IN body during routing and then failed. With the original exchange store in the dead letter queue it might be easier to manually re submit the org.apache.camel.Exchange again as the IN body is the same as when Camel received it. So you should be able to send the org.apache.camel.Exchange to the same input. By default this feature is off.",
          "title": "Use Original Message",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "optimisticLockRetryPolicy": {
      "type": "object",
      "title": "Optimistic Lock Retry Policy",
      "group": "configuration",
      "description": "To configure optimistic locking",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "maximumRetries": {
          "kind": "attribute",
          "type": "number",
          "description": "Sets the maximum number of retries",
          "title": "Maximum Retries",
          "optional": "true"
        },
        "retryDelay": {
          "kind": "attribute",
          "type": "integer",
          "description": "Sets the delay in millis between retries",
          "title": "Retry Delay",
          "optional": "true"
        },
        "maximumRetryDelay": {
          "kind": "attribute",
          "type": "integer",
          "description": "Sets the upper value of retry in millis between retries when using exponential or random backoff",
          "title": "Maximum Retry Delay",
          "optional": "true"
        },
        "exponentialBackOff": {
          "kind": "attribute",
          "type": "bool",
          "description": "Enable exponential backoff",
          "title": "Exponential Back Off",
          "optional": "true"
        },
        "randomBackOff": {
          "kind": "attribute",
          "type": "bool",
          "description": "Enables random backoff",
          "title": "Random Back Off",
          "optional": "true"
        }
      }
    },
    "otherwise": {
      "type": "object",
      "title": "Otherwise",
      "group": "eip,routing",
      "description": "Route to be executed when all other choices evaluate to false",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "packageScan": {
      "type": "object",
      "title": "Package Scan",
      "group": "configuration",
      "description": "Scans for Java org.apache.camel.builder.RouteBuilder classes in java packages",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "package": {
          "kind": "element",
          "type": "array",
          "description": "Sets the java package names to use for scanning for route builder classes",
          "title": "Package",
          "optional": "false"
        },
        "excludes": {
          "kind": "element",
          "type": "array",
          "description": "Exclude finding route builder from these java package names.",
          "title": "Excludes",
          "optional": "true"
        },
        "includes": {
          "kind": "element",
          "type": "array",
          "description": "Include finding route builder from these java package names.",
          "title": "Includes",
          "optional": "true"
        }
      }
    },
    "pipeline": {
      "type": "object",
      "title": "Pipeline",
      "group": "eip,routing",
      "description": "Routes the message to a sequence of processors.",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "policy": {
      "type": "object",
      "title": "Policy",
      "group": "configuration",
      "description": "Defines a policy the route will use",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets a reference to use for lookup the policy in the registry.",
          "title": "Ref",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "pollEnrich": {
      "type": "object",
      "title": "Poll Enrich",
      "group": "eip,transformation",
      "description": "Enriches messages with data polled from a secondary resource",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "The endpoint uri for the external service to poll enrich from. You must use either uri or ref.",
          "title": "Uri",
          "optional": "true"
        },
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to the endpoint for the external service to poll enrich from. You must use either uri or ref.",
          "title": "Ref",
          "optional": "true"
        },
        "timeout": {
          "kind": "attribute",
          "type": "integer",
          "description": "Timeout in millis when polling from the external service. The timeout has influence about the poll enrich behavior. It basically operations in three different modes: negative value - Waits until a message is available and then returns it. Warning that this method could block indefinitely if no messages are available. 0 - Attempts to receive a message exchange immediately without waiting and returning null if a message exchange is not available yet. positive value - Attempts to receive a message exchange waiting up to the given timeout to expire if a message is not yet available. Returns null if timed out The default value is -1 and therefore the method could block indefinitely and therefore its recommended to use a timeout value",
          "title": "Timeout",
          "optional": "true"
        },
        "strategyRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to an AggregationStrategy to be used to merge the reply from the external service into a single outgoing message. By default Camel will use the reply from the external service as outgoing message.",
          "title": "Strategy Ref",
          "optional": "true"
        },
        "strategyMethodName": {
          "kind": "attribute",
          "type": "string",
          "description": "This option can be used to explicit declare the method name to use when using POJOs as the AggregationStrategy.",
          "title": "Strategy Method Name",
          "optional": "true"
        },
        "strategyMethodAllowNull": {
          "kind": "attribute",
          "type": "bool",
          "description": "If this option is false then the aggregate method is not used if there was no data to enrich. If this option is true then null values is used as the oldExchange (when no data to enrich) when using POJOs as the AggregationStrategy.",
          "title": "Strategy Method Allow Null",
          "optional": "true"
        },
        "aggregateOnException": {
          "kind": "attribute",
          "type": "bool",
          "description": "If this option is false then the aggregate method is not used if there was an exception thrown while trying to retrieve the data to enrich from the resource. Setting this option to true allows end users to control what to do if there was an exception in the aggregate method. For example to suppress the exception or set a custom message body etc.",
          "title": "Aggregate On Exception",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "process": {
      "type": "object",
      "title": "Process",
      "group": "eip,endpoint",
      "description": "Calls a Camel processor.",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Reference to the Processor to lookup in the registry to use.",
          "title": "Ref",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "properties": {
      "type": "object",
      "title": "Properties",
      "group": "configuration,resequence",
      "description": "A series of key value pair",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "property": {
          "kind": "element",
          "type": "array",
          "description": "A series of properties as key value pairs",
          "title": "Property",
          "optional": "true"
        }
      }
    },
    "property": {
      "type": "object",
      "title": "Property",
      "group": "configuration,resequence",
      "description": "A key value pair",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "key": {
          "kind": "attribute",
          "type": "string",
          "description": "Property key",
          "title": "Key",
          "optional": "false"
        },
        "value": {
          "kind": "attribute",
          "type": "string",
          "description": "Property value",
          "title": "Value",
          "optional": "false"
        }
      }
    },
    "random": {
      "type": "object",
      "title": "Random",
      "group": "configuration,loadbalance",
      "description": "Random load balancer",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "recipientList": {
      "type": "object",
      "title": "Recipient List",
      "group": "eip,endpoint,routing",
      "description": "Routes messages to a number of dynamically specified recipients (dynamic to)",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "delimiter": {
          "kind": "attribute",
          "type": "string",
          "description": "Delimiter used if the Expression returned multiple endpoints. Can be turned off using the value false. The default value is",
          "title": "Delimiter",
          "optional": "true"
        },
        "parallelProcessing": {
          "kind": "attribute",
          "type": "bool",
          "description": "If enabled then sending messages to the recipients occurs concurrently. Note the caller thread will still wait until all messages has been fully processed before it continues. Its only the sending and processing the replies from the recipients which happens concurrently.",
          "title": "Parallel Processing",
          "optional": "true"
        },
        "strategyRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets a reference to the AggregationStrategy to be used to assemble the replies from the recipients into a single outgoing message from the RecipientList. By default Camel will use the last reply as the outgoing message. You can also use a POJO as the AggregationStrategy",
          "title": "Strategy Ref",
          "optional": "true"
        },
        "strategyMethodName": {
          "kind": "attribute",
          "type": "string",
          "description": "This option can be used to explicit declare the method name to use when using POJOs as the AggregationStrategy.",
          "title": "Strategy Method Name",
          "optional": "true"
        },
        "strategyMethodAllowNull": {
          "kind": "attribute",
          "type": "bool",
          "description": "If this option is false then the aggregate method is not used if there was no data to enrich. If this option is true then null values is used as the oldExchange (when no data to enrich) when using POJOs as the AggregationStrategy",
          "title": "Strategy Method Allow Null",
          "optional": "true"
        },
        "executorServiceRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to a custom Thread Pool to be used for parallel processing. Notice if you set this option then parallel processing is automatic implied and you do not have to enable that option as well.",
          "title": "Executor Service Ref",
          "optional": "true"
        },
        "stopOnException": {
          "kind": "attribute",
          "type": "bool",
          "description": "Will now stop further processing if an exception or failure occurred during processing of an org.apache.camel.Exchange and the caused exception will be thrown. Will also stop if processing the exchange failed (has a fault message) or an exception was thrown and handled by the error handler (such as using onException). In all situations the recipient list will stop further processing. This is the same behavior as in pipeline which is used by the routing engine. The default behavior is to not stop but continue processing till the end",
          "title": "Stop On Exception",
          "optional": "true"
        },
        "ignoreInvalidEndpoints": {
          "kind": "attribute",
          "type": "bool",
          "description": "Ignore the invalidate endpoint exception when try to create a producer with that endpoint",
          "title": "Ignore Invalid Endpoints",
          "optional": "true"
        },
        "streaming": {
          "kind": "attribute",
          "type": "bool",
          "description": "If enabled then Camel will process replies out-of-order eg in the order they come back. If disabled Camel will process replies in the same order as defined by the recipient list.",
          "title": "Streaming",
          "optional": "true"
        },
        "timeout": {
          "kind": "attribute",
          "type": "integer",
          "description": "Sets a total timeout specified in millis when using parallel processing. If the Recipient List hasn't been able to send and process all replies within the given timeframe then the timeout triggers and the Recipient List breaks out and continues. Notice if you provide a TimeoutAwareAggregationStrategy then the timeout method is invoked before breaking out. If the timeout is reached with running tasks still remaining certain tasks for which it is difficult for Camel to shut down in a graceful manner may continue to run. So use this option with a bit of care.",
          "title": "Timeout",
          "optional": "true"
        },
        "onPrepareRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Uses the Processor when preparing the org.apache.camel.Exchange to be send. This can be used to deep-clone messages that should be send or any custom logic needed before the exchange is send.",
          "title": "On Prepare Ref",
          "optional": "true"
        },
        "shareUnitOfWork": {
          "kind": "attribute",
          "type": "bool",
          "description": "Shares the org.apache.camel.spi.UnitOfWork with the parent and each of the sub messages. Recipient List will by default not share unit of work between the parent exchange and each recipient exchange. This means each sub exchange has its own individual unit of work.",
          "title": "Share Unit Of Work",
          "optional": "true"
        },
        "cacheSize": {
          "kind": "attribute",
          "type": "number",
          "description": "Sets the maximum size used by the org.apache.camel.impl.ProducerCache which is used to cache and reuse producers when using this recipient list when uris are reused.",
          "title": "Cache Size",
          "optional": "true"
        },
        "parallelAggregate": {
          "kind": "attribute",
          "type": "bool",
          "description": "If enabled then the aggregate method on AggregationStrategy can be called concurrently. Notice that this would require the implementation of AggregationStrategy to be implemented as thread-safe. By default this is false meaning that Camel synchronizes the call to the aggregate method. Though in some use-cases this can be used to archive higher performance when the AggregationStrategy is implemented as thread-safe.",
          "title": "Parallel Aggregate",
          "optional": "true"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression that returns which endpoints (url) to send the message to (the recipients). If the expression return an empty value then the message is not sent to any recipients.",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "redeliveryPolicy": {
      "type": "object",
      "title": "Redelivery Policy",
      "group": "configuration",
      "description": "To configure re-delivery for error handling",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "maximumRedeliveries": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the maximum redeliveries x = redeliver at most x times 0 = no redeliveries -1 = redeliver forever",
          "title": "Maximum Redeliveries",
          "optional": "true"
        },
        "redeliveryDelay": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the initial redelivery delay",
          "title": "Redelivery Delay",
          "optional": "true"
        },
        "asyncDelayedRedelivery": {
          "kind": "attribute",
          "type": "string",
          "description": "Allow synchronous delayed redelivery.",
          "title": "Async Delayed Redelivery",
          "optional": "true"
        },
        "backOffMultiplier": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the back off multiplier",
          "title": "Back Off Multiplier",
          "optional": "true"
        },
        "useExponentialBackOff": {
          "kind": "attribute",
          "type": "string",
          "description": "Turn on exponential backk off",
          "title": "Use Exponential Back Off",
          "optional": "true"
        },
        "collisionAvoidanceFactor": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the collision avoidance factor",
          "title": "Collision Avoidance Factor",
          "optional": "true"
        },
        "useCollisionAvoidance": {
          "kind": "attribute",
          "type": "string",
          "description": "Turn on collision avoidance.",
          "title": "Use Collision Avoidance",
          "optional": "true"
        },
        "maximumRedeliveryDelay": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the maximum delay between redelivery",
          "title": "Maximum Redelivery Delay",
          "optional": "true"
        },
        "retriesExhaustedLogLevel": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the logging level to use when retries has exhausted",
          "title": "Retries Exhausted Log Level",
          "optional": "true"
        },
        "retryAttemptedLogLevel": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the logging level to use for logging retry attempts",
          "title": "Retry Attempted Log Level",
          "optional": "true"
        },
        "logRetryAttempted": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets whether retry attempts should be logged or not. Can be used to include or reduce verbose.",
          "title": "Log Retry Attempted",
          "optional": "true"
        },
        "logStackTrace": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets whether stack traces should be logged. Can be used to include or reduce verbose.",
          "title": "Log Stack Trace",
          "optional": "true"
        },
        "logRetryStackTrace": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets whether stack traces should be logged when an retry attempt failed. Can be used to include or reduce verbose.",
          "title": "Log Retry Stack Trace",
          "optional": "true"
        },
        "logHandled": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets whether handled exceptions should be logged or not. Can be used to include or reduce verbose.",
          "title": "Log Handled",
          "optional": "true"
        },
        "logNewException": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets whether new exceptions should be logged or not. Can be used to include or reduce verbose. A new exception is an exception that was thrown while handling a previous exception.",
          "title": "Log New Exception",
          "optional": "true"
        },
        "logContinued": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets whether continued exceptions should be logged or not. Can be used to include or reduce verbose.",
          "title": "Log Continued",
          "optional": "true"
        },
        "logExhausted": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets whether exhausted exceptions should be logged or not. Can be used to include or reduce verbose.",
          "title": "Log Exhausted",
          "optional": "true"
        },
        "logExhaustedMessageHistory": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets whether exhausted exceptions should be logged including message history or not (supports property placeholders). Can be used to include or reduce verbose.",
          "title": "Log Exhausted Message History",
          "optional": "true"
        },
        "disableRedelivery": {
          "kind": "attribute",
          "type": "string",
          "description": "Disables redelivery (same as setting maximum redeliveries to 0)",
          "title": "Disable Redelivery",
          "optional": "true"
        },
        "delayPattern": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the delay pattern with delay intervals.",
          "title": "Delay Pattern",
          "optional": "true"
        },
        "allowRedeliveryWhileStopping": {
          "kind": "attribute",
          "type": "string",
          "description": "Controls whether to allow redelivery while stopping/shutting down a route that uses error handling.",
          "title": "Allow Redelivery While Stopping",
          "optional": "true"
        },
        "exchangeFormatterRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the reference of the instance of org.apache.camel.spi.ExchangeFormatter to generate the log message from exchange.",
          "title": "Exchange Formatter Ref",
          "optional": "true"
        }
      }
    },
    "removeHeader": {
      "type": "object",
      "title": "Remove Header",
      "group": "eip,transformation",
      "description": "Removes a named header from the message",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "headerName": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of header to remove",
          "title": "Header Name",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "removeHeaders": {
      "type": "object",
      "title": "Remove Headers",
      "group": "eip,transformation",
      "description": "Removes message headers whose name matches a specified pattern",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "pattern": {
          "kind": "attribute",
          "type": "string",
          "description": "Name or pattern of headers to remove",
          "title": "Pattern",
          "optional": "false"
        },
        "excludePattern": {
          "kind": "attribute",
          "type": "string",
          "description": "Name or patter of headers to not remove",
          "title": "Exclude Pattern",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "removeProperties": {
      "type": "object",
      "title": "Remove Properties",
      "group": "eip,transformation",
      "description": "Removes message exchange properties whose name matches a specified pattern",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "pattern": {
          "kind": "attribute",
          "type": "string",
          "description": "Name or pattern of properties to remove",
          "title": "Pattern",
          "optional": "false"
        },
        "excludePattern": {
          "kind": "attribute",
          "type": "string",
          "description": "Name or pattern of properties to not remove",
          "title": "Exclude Pattern",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "removeProperty": {
      "type": "object",
      "title": "Remove Property",
      "group": "eip,transformation",
      "description": "Removes a named property from the message exchange",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "propertyName": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of property to remove",
          "title": "Property Name",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "resequence": {
      "type": "object",
      "title": "Resequence",
      "group": "eip,routing",
      "description": "Resequences (re-order) messages based on an expression",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "resequencerConfig": {
          "kind": "element",
          "type": "object",
          "description": "To configure the resequencer in using either batch or stream configuration. Will by default use batch configuration.",
          "title": "Resequencer Config",
          "optional": "true"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression to use for re-ordering the messages such as a header with a sequence number",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "restContextRef": {
      "type": "object",
      "title": "Rest Context Ref",
      "group": "configuration,rest",
      "description": "To refer to an XML file with rest services defined using the rest-dsl",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Reference to the rest-dsl",
          "title": "Ref",
          "optional": "false"
        }
      }
    },
    "rollback": {
      "type": "object",
      "title": "Rollback",
      "group": "eip,routing",
      "description": "Forces a rollback by stopping routing the message",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "markRollbackOnly": {
          "kind": "attribute",
          "type": "bool",
          "description": "Mark the transaction for rollback only (cannot be overruled to commit)",
          "title": "Mark Rollback Only",
          "optional": "true"
        },
        "markRollbackOnlyLast": {
          "kind": "attribute",
          "type": "bool",
          "description": "Mark only last sub transaction for rollback only. When using sub transactions (if the transaction manager support this)",
          "title": "Mark Rollback Only Last",
          "optional": "true"
        },
        "message": {
          "kind": "attribute",
          "type": "string",
          "description": "Message to use in rollback exception",
          "title": "Message",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "roundRobin": {
      "type": "object",
      "title": "Round Robin",
      "group": "configuration,loadbalance",
      "description": "Round robin load balancer",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "route": {
      "type": "object",
      "title": "Route",
      "group": "configuration",
      "description": "A Camel route",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "group": {
          "kind": "attribute",
          "type": "string",
          "description": "The group that this route belongs to; could be the name of the RouteBuilder class or be explicitly configured in the XML. May be null.",
          "title": "Group",
          "optional": "true"
        },
        "streamCache": {
          "kind": "attribute",
          "type": "string",
          "description": "Whether stream caching is enabled on this route.",
          "title": "Stream Cache",
          "optional": "true"
        },
        "trace": {
          "kind": "attribute",
          "type": "string",
          "description": "Whether tracing is enabled on this route.",
          "title": "Trace",
          "optional": "true"
        },
        "messageHistory": {
          "kind": "attribute",
          "type": "string",
          "description": "Whether message history is enabled on this route.",
          "title": "Message History",
          "optional": "true"
        },
        "handleFault": {
          "kind": "attribute",
          "type": "string",
          "description": "Whether handle fault is enabled on this route.",
          "title": "Handle Fault",
          "optional": "true"
        },
        "delayer": {
          "kind": "attribute",
          "type": "string",
          "description": "Whether to slow down processing messages by a given delay in msec.",
          "title": "Delayer",
          "optional": "true"
        },
        "autoStartup": {
          "kind": "attribute",
          "type": "string",
          "description": "Whether to auto start this route",
          "title": "Auto Startup",
          "optional": "true"
        },
        "startupOrder": {
          "kind": "attribute",
          "type": "number",
          "description": "To configure the ordering of the routes being started",
          "title": "Startup Order",
          "optional": "true"
        },
        "errorHandlerRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the bean ref name of the error handler builder to use on this route",
          "title": "Error Handler Ref",
          "optional": "true"
        },
        "routePolicyRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Reference to custom org.apache.camel.spi.RoutePolicy to use by the route. Multiple policies can be configured by separating values using comma.",
          "title": "Route Policy Ref",
          "optional": "true"
        },
        "shutdownRoute": {
          "kind": "attribute",
          "type": "string",
          "description": "To control how to shutdown the route.",
          "title": "Shutdown Route",
          "optional": "true"
        },
        "shutdownRunningTask": {
          "kind": "attribute",
          "type": "string",
          "description": "To control how to shutdown the route.",
          "title": "Shutdown Running Task",
          "optional": "true"
        },
        "inputs": {
          "kind": "element",
          "type": "array",
          "description": "Input to the route.",
          "title": "Inputs",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "routeBuilder": {
      "type": "object",
      "title": "Route Builder",
      "group": "configuration",
      "description": "To refer to a Java org.apache.camel.builder.RouteBuilder instance to use.",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Reference to the route builder instance",
          "title": "Ref",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "routeContextRef": {
      "type": "object",
      "title": "Route Context Ref",
      "group": "configuration",
      "description": "To refer to an XML file with routes defined using the xml-dsl",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Reference to the routes in the xml dsl",
          "title": "Ref",
          "optional": "false"
        }
      }
    },
    "routes": {
      "type": "object",
      "title": "Routes",
      "group": "configuration",
      "description": "A series of Camel routes",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "routingSlip": {
      "type": "object",
      "title": "Routing Slip",
      "group": "eip,endpoint,routing",
      "description": "Routes a message through a series of steps that are pre-determined (the slip)",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "uriDelimiter": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the uri delimiter to use",
          "title": "Uri Delimiter",
          "optional": "true"
        },
        "ignoreInvalidEndpoints": {
          "kind": "attribute",
          "type": "bool",
          "description": "Ignore the invalidate endpoint exception when try to create a producer with that endpoint",
          "title": "Ignore Invalid Endpoints",
          "optional": "true"
        },
        "cacheSize": {
          "kind": "attribute",
          "type": "number",
          "description": "Sets the maximum size used by the org.apache.camel.impl.ProducerCache which is used to cache and reuse producers when using this recipient list when uris are reused.",
          "title": "Cache Size",
          "optional": "true"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression to define the routing slip which defines which endpoints to route the message in a pipeline style. Notice the expression is evaluated once if you want a more dynamic style then the dynamic router eip is a better choice.",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "sample": {
      "type": "object",
      "title": "Sample",
      "group": "eip,routing",
      "description": "Extract a sample of the messages passing through a route",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "samplePeriod": {
          "kind": "attribute",
          "type": "integer",
          "description": "Sets the sample period during which only a single Exchange will pass through.",
          "title": "Sample Period",
          "optional": "true"
        },
        "messageFrequency": {
          "kind": "attribute",
          "type": "integer",
          "description": "Sets the sample message count which only a single Exchange will pass through after this many received.",
          "title": "Message Frequency",
          "optional": "true"
        },
        "units": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the time units for the sample period defaulting to seconds.",
          "title": "Units",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "setBody": {
      "type": "object",
      "title": "Set Body",
      "group": "eip,transformation",
      "description": "Sets the contents of the message body",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression that returns the new body to use",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "setExchangePattern": {
      "type": "object",
      "title": "Set Exchange Pattern",
      "group": "configuration",
      "description": "Sets the exchange pattern on the message exchange",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "pattern": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the new exchange pattern of the Exchange to be used from this point forward",
          "title": "Pattern",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "setFaultBody": {
      "type": "object",
      "title": "Set Fault Body",
      "group": "eip,transformation",
      "description": "Sets the contents of a fault message's body",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression that returns the new fault body to use",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "setHeader": {
      "type": "object",
      "title": "Set Header",
      "group": "eip,transformation",
      "description": "Sets the value of a message header",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "headerName": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of message header to set a new value",
          "title": "Header Name",
          "optional": "false"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression to return the value of the header",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "setOutHeader": {
      "type": "object",
      "title": "Set Out Header",
      "group": "eip,transformation",
      "description": "Sets the value of a header on the outbound message",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "headerName": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of message header to set a new value",
          "title": "Header Name",
          "optional": "false"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression to return the value of the header",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "setProperty": {
      "type": "object",
      "title": "Set Property",
      "group": "eip,transformation",
      "description": "Sets a named property on the message exchange",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "propertyName": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of exchange property to set a new value",
          "title": "Property Name",
          "optional": "false"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression to return the value of the message exchange property",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "sort": {
      "type": "object",
      "title": "Sort",
      "group": "eip,routing",
      "description": "Sorts the contents of the message",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "comparatorRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets a reference to lookup for the comparator to use for sorting",
          "title": "Comparator Ref",
          "optional": "true"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Optional expression to sort by something else than the message body",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "split": {
      "type": "object",
      "title": "Split",
      "group": "eip,routing",
      "description": "Splits a single message into many sub-messages.",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "parallelProcessing": {
          "kind": "attribute",
          "type": "bool",
          "description": "If enabled then processing each splitted messages occurs concurrently. Note the caller thread will still wait until all messages has been fully processed before it continues. Its only processing the sub messages from the splitter which happens concurrently.",
          "title": "Parallel Processing",
          "optional": "true"
        },
        "strategyRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets a reference to the AggregationStrategy to be used to assemble the replies from the splitted messages into a single outgoing message from the Splitter. By default Camel will use the original incoming message to the splitter (leave it unchanged). You can also use a POJO as the AggregationStrategy",
          "title": "Strategy Ref",
          "optional": "true"
        },
        "strategyMethodName": {
          "kind": "attribute",
          "type": "string",
          "description": "This option can be used to explicit declare the method name to use when using POJOs as the AggregationStrategy.",
          "title": "Strategy Method Name",
          "optional": "true"
        },
        "strategyMethodAllowNull": {
          "kind": "attribute",
          "type": "bool",
          "description": "If this option is false then the aggregate method is not used if there was no data to enrich. If this option is true then null values is used as the oldExchange (when no data to enrich) when using POJOs as the AggregationStrategy",
          "title": "Strategy Method Allow Null",
          "optional": "true"
        },
        "executorServiceRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to a custom Thread Pool to be used for parallel processing. Notice if you set this option then parallel processing is automatic implied and you do not have to enable that option as well.",
          "title": "Executor Service Ref",
          "optional": "true"
        },
        "streaming": {
          "kind": "attribute",
          "type": "bool",
          "description": "When in streaming mode then the splitter splits the original message on-demand and each splitted message is processed one by one. This reduces memory usage as the splitter do not split all the messages first but then we do not know the total size and therefore the link org.apache.camel.ExchangeSPLIT_SIZE is empty. In non-streaming mode (default) the splitter will split each message first to know the total size and then process each message one by one. This requires to keep all the splitted messages in memory and therefore requires more memory. The total size is provided in the link org.apache.camel.ExchangeSPLIT_SIZE header. The streaming mode also affects the aggregation behavior. If enabled then Camel will process replies out-of-order eg in the order they come back. If disabled Camel will process replies in the same order as the messages was splitted.",
          "title": "Streaming",
          "optional": "true"
        },
        "stopOnException": {
          "kind": "attribute",
          "type": "bool",
          "description": "Will now stop further processing if an exception or failure occurred during processing of an org.apache.camel.Exchange and the caused exception will be thrown. Will also stop if processing the exchange failed (has a fault message) or an exception was thrown and handled by the error handler (such as using onException). In all situations the splitter will stop further processing. This is the same behavior as in pipeline which is used by the routing engine. The default behavior is to not stop but continue processing till the end",
          "title": "Stop On Exception",
          "optional": "true"
        },
        "timeout": {
          "kind": "attribute",
          "type": "integer",
          "description": "Sets a total timeout specified in millis when using parallel processing. If the Splitter hasn't been able to split and process all the sub messages within the given timeframe then the timeout triggers and the Splitter breaks out and continues. Notice if you provide a TimeoutAwareAggregationStrategy then the timeout method is invoked before breaking out. If the timeout is reached with running tasks still remaining certain tasks for which it is difficult for Camel to shut down in a graceful manner may continue to run. So use this option with a bit of care.",
          "title": "Timeout",
          "optional": "true"
        },
        "onPrepareRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Uses the Processor when preparing the org.apache.camel.Exchange to be send. This can be used to deep-clone messages that should be send or any custom logic needed before the exchange is send.",
          "title": "On Prepare Ref",
          "optional": "true"
        },
        "shareUnitOfWork": {
          "kind": "attribute",
          "type": "bool",
          "description": "Shares the org.apache.camel.spi.UnitOfWork with the parent and each of the sub messages. Splitter will by default not share unit of work between the parent exchange and each splitted exchange. This means each splitted exchange has its own individual unit of work.",
          "title": "Share Unit Of Work",
          "optional": "true"
        },
        "parallelAggregate": {
          "kind": "attribute",
          "type": "bool",
          "description": "If enabled then the aggregate method on AggregationStrategy can be called concurrently. Notice that this would require the implementation of AggregationStrategy to be implemented as thread-safe. By default this is false meaning that Camel synchronizes the call to the aggregate method. Though in some use-cases this can be used to archive higher performance when the AggregationStrategy is implemented as thread-safe.",
          "title": "Parallel Aggregate",
          "optional": "true"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression of how to split the message body such as as-is using a tokenizer or using an xpath.",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "sticky": {
      "type": "object",
      "title": "Sticky",
      "group": "configuration,loadbalance",
      "description": "Sticky load balancer",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "correlationExpression": {
          "kind": "expression",
          "type": "expression",
          "description": "The correlation expression to use to calculate the correlation key",
          "title": "Correlation Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "stop": {
      "type": "object",
      "title": "Stop",
      "group": "eip,routing",
      "description": "Stops the processing of the current message",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "stream-config": {
      "type": "object",
      "title": "Stream-config",
      "group": "configuration,resequence",
      "description": "Configures stream-processing resequence eip.",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "capacity": {
          "kind": "attribute",
          "type": "number",
          "description": "Sets the capacity of the resequencer's inbound queue.",
          "title": "Capacity",
          "optional": "true"
        },
        "timeout": {
          "kind": "attribute",
          "type": "integer",
          "description": "Sets minimum time to wait for missing elements (messages).",
          "title": "Timeout",
          "optional": "true"
        },
        "ignoreInvalidExchanges": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to ignore invalid exchanges",
          "title": "Ignore Invalid Exchanges",
          "optional": "true"
        },
        "comparatorRef": {
          "kind": "attribute",
          "type": "string",
          "description": "To use a custom comparator",
          "title": "Comparator Ref",
          "optional": "true"
        },
        "rejectOld": {
          "kind": "attribute",
          "type": "bool",
          "description": "If true throws an exception when messages older than the last delivered message are processed",
          "title": "Reject Old",
          "optional": "true"
        }
      }
    },
    "threadPoolProfile": {
      "type": "object",
      "title": "Thread Pool Profile",
      "group": "configuration",
      "description": "To configure thread pools",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "defaultProfile": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether this profile is the default thread pool profile",
          "title": "Default Profile",
          "optional": "true"
        },
        "poolSize": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the core pool size",
          "title": "Pool Size",
          "optional": "true"
        },
        "maxPoolSize": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the maximum pool size",
          "title": "Max Pool Size",
          "optional": "true"
        },
        "keepAliveTime": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the keep alive time for idle threads in the pool",
          "title": "Keep Alive Time",
          "optional": "true"
        },
        "maxQueueSize": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the maximum number of tasks in the work queue. Use -1 or Integer.MAX_VALUE for an unbounded queue",
          "title": "Max Queue Size",
          "optional": "true"
        },
        "allowCoreThreadTimeOut": {
          "kind": "attribute",
          "type": "string",
          "description": "Whether idle core threads is allowed to timeout and therefore can shrink the pool size below the core pool size Is by default false",
          "title": "Allow Core Thread Time Out",
          "optional": "true"
        },
        "rejectedPolicy": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the handler for tasks which cannot be executed by the thread pool.",
          "title": "Rejected Policy",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "threads": {
      "type": "object",
      "title": "Threads",
      "group": "eip,routing",
      "description": "Specifies that all steps after this node are processed asynchronously",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "executorServiceRef": {
          "kind": "attribute",
          "type": "string",
          "description": "To refer to a custom thread pool or use a thread pool profile (as overlay)",
          "title": "Executor Service Ref",
          "optional": "true"
        },
        "poolSize": {
          "kind": "attribute",
          "type": "number",
          "description": "Sets the core pool size",
          "title": "Pool Size",
          "optional": "true"
        },
        "maxPoolSize": {
          "kind": "attribute",
          "type": "number",
          "description": "Sets the maximum pool size",
          "title": "Max Pool Size",
          "optional": "true"
        },
        "keepAliveTime": {
          "kind": "attribute",
          "type": "integer",
          "description": "Sets the keep alive time for idle threads",
          "title": "Keep Alive Time",
          "optional": "true"
        },
        "timeUnit": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the keep alive time unit. By default SECONDS is used.",
          "title": "Time Unit",
          "optional": "true"
        },
        "maxQueueSize": {
          "kind": "attribute",
          "type": "number",
          "description": "Sets the maximum number of tasks in the work queue. Use -1 or Integer.MAX_VALUE for an unbounded queue",
          "title": "Max Queue Size",
          "optional": "true"
        },
        "allowCoreThreadTimeOut": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether idle core threads is allowed to timeout and therefore can shrink the pool size below the core pool size Is by default false",
          "title": "Allow Core Thread Time Out",
          "optional": "true"
        },
        "threadName": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the thread name to use.",
          "title": "Thread Name",
          "optional": "true"
        },
        "rejectedPolicy": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the handler for tasks which cannot be executed by the thread pool.",
          "title": "Rejected Policy",
          "optional": "true"
        },
        "callerRunsWhenRejected": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the caller should run the task when it was rejected by the thread pool. Is by default true",
          "title": "Caller Runs When Rejected",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "throttle": {
      "type": "object",
      "title": "Throttle",
      "group": "eip,routing",
      "description": "Controls the rate at which messages are passed to the next node in the route",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "executorServiceRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the ExecutorService which could be used by throttle definition",
          "title": "Executor Service Ref",
          "optional": "true"
        },
        "timePeriodMillis": {
          "kind": "attribute",
          "type": "integer",
          "description": "Sets the time period during which the maximum request count is valid for",
          "title": "Time Period Millis",
          "optional": "true"
        },
        "asyncDelayed": {
          "kind": "attribute",
          "type": "bool",
          "description": "Enables asynchronous delay which means the thread will no block while delaying.",
          "title": "Async Delayed",
          "optional": "true"
        },
        "callerRunsWhenRejected": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the caller should run the task when it was rejected by the thread pool. Is by default true",
          "title": "Caller Runs When Rejected",
          "optional": "true"
        },
        "rejectExecution": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not throttler throws the ThrottlerRejectedExecutionException when the exchange exceeds the request limit Is by default false",
          "title": "Reject Execution",
          "optional": "true"
        },
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression to configure the maximum number of messages to throttle per request",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "throwException": {
      "type": "object",
      "title": "Throw Exception",
      "group": "error",
      "description": "Throws an exception",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Reference to the exception instance to lookup from the registry to throw",
          "title": "Ref",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "to": {
      "type": "object",
      "title": "To",
      "group": "eip,endpoint,routing",
      "description": "Sends the message to an endpoint",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "pattern": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the optional ExchangePattern used to invoke this endpoint",
          "title": "Pattern",
          "optional": "true"
        },
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the uri of the endpoint to send to.",
          "title": "Uri",
          "optional": "true"
        },
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the reference of the endpoint to send to.",
          "title": "Ref",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "topic": {
      "type": "object",
      "title": "Topic",
      "group": "configuration,loadbalance",
      "description": "Topic load balancer",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "transacted": {
      "type": "object",
      "title": "Transacted",
      "group": "configuration",
      "description": "Enables transaction on the route",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets a reference to use for lookup the policy in the registry.",
          "title": "Ref",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "transform": {
      "type": "object",
      "title": "Transform",
      "group": "eip,transformation",
      "description": "Transforms the message body based on an expression",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression to return the transformed message body (the new message body to use)",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "unmarshal": {
      "type": "object",
      "title": "Unmarshal",
      "group": "eip,transformation",
      "description": "Converts the message data received from the wire into a format that Apache Camel processors can consume",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "dataFormatType": {
          "kind": "element",
          "type": "object",
          "description": "The data format to be used",
          "title": "Data Format Type",
          "optional": "false"
        },
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "To refer to a custom data format to use as unmarshaller",
          "title": "Ref",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "validate": {
      "type": "object",
      "title": "Validate",
      "group": "eip,transformation",
      "description": "Validates a message based on an expression",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression to use for validation as a predicate. The expression should return either true or false. If returning false the message is invalid and an exception is thrown.",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "weighted": {
      "type": "object",
      "title": "Weighted",
      "group": "configuration,loadbalance",
      "description": "Weighted load balancer",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "roundRobin": {
          "kind": "attribute",
          "type": "bool",
          "description": "To enable round robin mode. By default the weighted distribution mode is used. The default value is false.",
          "title": "Round Robin",
          "optional": "true"
        },
        "distributionRatio": {
          "kind": "attribute",
          "type": "string",
          "description": "The distribution ratio is a delimited String consisting on integer weights separated by delimiters for example 235. The distributionRatio must match the number of endpoints and/or processors specified in the load balancer list.",
          "title": "Distribution Ratio",
          "optional": "false"
        },
        "distributionRatioDelimiter": {
          "kind": "attribute",
          "type": "string",
          "description": "Delimiter used to specify the distribution ratio. The default value is",
          "title": "Distribution Ratio Delimiter",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "when": {
      "type": "object",
      "title": "When",
      "group": "eip,routing",
      "description": "Triggers a route when an expression evaluates to true",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression used as the predicate to evaluate whether this when should trigger and route the message or not.",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "whenSkipSendToEndpoint": {
      "type": "object",
      "title": "When Skip Send To Endpoint",
      "group": "configuration",
      "description": "Predicate to determine if the message should be sent or not to the endpoint when using interceptSentToEndpoint.",
      "acceptInput": "true",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "expression": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression used as the predicate to evaluate whether the message should be sent or not to the endpoint",
          "title": "Expression",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "wireTap": {
      "type": "object",
      "title": "Wire Tap",
      "group": "eip,endpoint,routing",
      "description": "Routes a copy of a message (or creates a new message) to a secondary destination while continue routing the original message.",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Uri of the endpoint to use as wire tap",
          "title": "Uri",
          "optional": "true"
        },
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Reference of the endpoint to use as wire tap",
          "title": "Ref",
          "optional": "true"
        },
        "processorRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Reference to a Processor to use for creating a new body as the message to use for wire tapping",
          "title": "Processor Ref",
          "optional": "true"
        },
        "body": {
          "kind": "expression",
          "type": "expression",
          "description": "Expression used for creating a new body as the message to use for wire tapping",
          "title": "Body",
          "optional": "true"
        },
        "executorServiceRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Uses a custom thread pool",
          "title": "Executor Service Ref",
          "optional": "true"
        },
        "copy": {
          "kind": "attribute",
          "type": "bool",
          "description": "Uses a copy of the original exchange",
          "title": "Copy",
          "optional": "true"
        },
        "onPrepareRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Uses the Processor when preparing the org.apache.camel.Exchange to be send. This can be used to deep-clone messages that should be send or any custom logic needed before the exchange is send.",
          "title": "On Prepare Ref",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    }
  },
  "rests": {
    "delete": {
      "type": "object",
      "title": "Delete",
      "group": "rest",
      "description": "Rest DELETE command",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "method": {
          "kind": "attribute",
          "type": "string",
          "description": "The HTTP verb such as GET or POST",
          "title": "Method",
          "optional": "true"
        },
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Uri template of this REST service such as /id.",
          "title": "Uri",
          "optional": "true"
        },
        "consumes": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service consumes (accept as input) such as application/xml or application/json. This option will override what may be configured on a parent level",
          "title": "Consumes",
          "optional": "true"
        },
        "produces": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service produces (uses for output) such as application/xml or application/json This option will override what may be configured on a parent level",
          "title": "Produces",
          "optional": "true"
        },
        "bindingMode": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the binding mode to use. This option will override what may be configured on a parent level The default value is auto",
          "title": "Binding Mode",
          "optional": "true"
        },
        "skipBindingOnErrorCode": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to skip binding on output if there is a custom HTTP error code header. This allows to build custom error messages that do not bind to json / xml etc as success messages otherwise will do. This option will override what may be configured on a parent level",
          "title": "Skip Binding On Error Code",
          "optional": "true"
        },
        "enableCORS": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to enable CORS headers in the HTTP response. This option will override what may be configured on a parent level The default value is false.",
          "title": "Enable C O R S",
          "optional": "true"
        },
        "type": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from input to POJO for the incoming data This option will override what may be configured on a parent level",
          "title": "Type",
          "optional": "true"
        },
        "outType": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from POJO to output for the outgoing data This option will override what may be configured on a parent level",
          "title": "Out Type",
          "optional": "true"
        },
        "toOrRoute": {
          "kind": "element",
          "type": "object",
          "description": "To route from this REST service to a Camel endpoint or an inlined route",
          "title": "To Or Route",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "get": {
      "type": "object",
      "title": "Get",
      "group": "rest",
      "description": "Rest GET command",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "method": {
          "kind": "attribute",
          "type": "string",
          "description": "The HTTP verb such as GET or POST",
          "title": "Method",
          "optional": "true"
        },
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Uri template of this REST service such as /id.",
          "title": "Uri",
          "optional": "true"
        },
        "consumes": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service consumes (accept as input) such as application/xml or application/json. This option will override what may be configured on a parent level",
          "title": "Consumes",
          "optional": "true"
        },
        "produces": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service produces (uses for output) such as application/xml or application/json This option will override what may be configured on a parent level",
          "title": "Produces",
          "optional": "true"
        },
        "bindingMode": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the binding mode to use. This option will override what may be configured on a parent level The default value is auto",
          "title": "Binding Mode",
          "optional": "true"
        },
        "skipBindingOnErrorCode": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to skip binding on output if there is a custom HTTP error code header. This allows to build custom error messages that do not bind to json / xml etc as success messages otherwise will do. This option will override what may be configured on a parent level",
          "title": "Skip Binding On Error Code",
          "optional": "true"
        },
        "enableCORS": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to enable CORS headers in the HTTP response. This option will override what may be configured on a parent level The default value is false.",
          "title": "Enable C O R S",
          "optional": "true"
        },
        "type": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from input to POJO for the incoming data This option will override what may be configured on a parent level",
          "title": "Type",
          "optional": "true"
        },
        "outType": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from POJO to output for the outgoing data This option will override what may be configured on a parent level",
          "title": "Out Type",
          "optional": "true"
        },
        "toOrRoute": {
          "kind": "element",
          "type": "object",
          "description": "To route from this REST service to a Camel endpoint or an inlined route",
          "title": "To Or Route",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "head": {
      "type": "object",
      "title": "Head",
      "group": "rest",
      "description": "Rest HEAD command",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "method": {
          "kind": "attribute",
          "type": "string",
          "description": "The HTTP verb such as GET or POST",
          "title": "Method",
          "optional": "true"
        },
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Uri template of this REST service such as /id.",
          "title": "Uri",
          "optional": "true"
        },
        "consumes": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service consumes (accept as input) such as application/xml or application/json. This option will override what may be configured on a parent level",
          "title": "Consumes",
          "optional": "true"
        },
        "produces": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service produces (uses for output) such as application/xml or application/json This option will override what may be configured on a parent level",
          "title": "Produces",
          "optional": "true"
        },
        "bindingMode": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the binding mode to use. This option will override what may be configured on a parent level The default value is auto",
          "title": "Binding Mode",
          "optional": "true"
        },
        "skipBindingOnErrorCode": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to skip binding on output if there is a custom HTTP error code header. This allows to build custom error messages that do not bind to json / xml etc as success messages otherwise will do. This option will override what may be configured on a parent level",
          "title": "Skip Binding On Error Code",
          "optional": "true"
        },
        "enableCORS": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to enable CORS headers in the HTTP response. This option will override what may be configured on a parent level The default value is false.",
          "title": "Enable C O R S",
          "optional": "true"
        },
        "type": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from input to POJO for the incoming data This option will override what may be configured on a parent level",
          "title": "Type",
          "optional": "true"
        },
        "outType": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from POJO to output for the outgoing data This option will override what may be configured on a parent level",
          "title": "Out Type",
          "optional": "true"
        },
        "toOrRoute": {
          "kind": "element",
          "type": "object",
          "description": "To route from this REST service to a Camel endpoint or an inlined route",
          "title": "To Or Route",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "post": {
      "type": "object",
      "title": "Post",
      "group": "rest",
      "description": "Rest POST command",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "method": {
          "kind": "attribute",
          "type": "string",
          "description": "The HTTP verb such as GET or POST",
          "title": "Method",
          "optional": "true"
        },
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Uri template of this REST service such as /id.",
          "title": "Uri",
          "optional": "true"
        },
        "consumes": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service consumes (accept as input) such as application/xml or application/json. This option will override what may be configured on a parent level",
          "title": "Consumes",
          "optional": "true"
        },
        "produces": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service produces (uses for output) such as application/xml or application/json This option will override what may be configured on a parent level",
          "title": "Produces",
          "optional": "true"
        },
        "bindingMode": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the binding mode to use. This option will override what may be configured on a parent level The default value is auto",
          "title": "Binding Mode",
          "optional": "true"
        },
        "skipBindingOnErrorCode": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to skip binding on output if there is a custom HTTP error code header. This allows to build custom error messages that do not bind to json / xml etc as success messages otherwise will do. This option will override what may be configured on a parent level",
          "title": "Skip Binding On Error Code",
          "optional": "true"
        },
        "enableCORS": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to enable CORS headers in the HTTP response. This option will override what may be configured on a parent level The default value is false.",
          "title": "Enable C O R S",
          "optional": "true"
        },
        "type": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from input to POJO for the incoming data This option will override what may be configured on a parent level",
          "title": "Type",
          "optional": "true"
        },
        "outType": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from POJO to output for the outgoing data This option will override what may be configured on a parent level",
          "title": "Out Type",
          "optional": "true"
        },
        "toOrRoute": {
          "kind": "element",
          "type": "object",
          "description": "To route from this REST service to a Camel endpoint or an inlined route",
          "title": "To Or Route",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "put": {
      "type": "object",
      "title": "Put",
      "group": "rest",
      "description": "Rest PUT command",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "method": {
          "kind": "attribute",
          "type": "string",
          "description": "The HTTP verb such as GET or POST",
          "title": "Method",
          "optional": "true"
        },
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Uri template of this REST service such as /id.",
          "title": "Uri",
          "optional": "true"
        },
        "consumes": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service consumes (accept as input) such as application/xml or application/json. This option will override what may be configured on a parent level",
          "title": "Consumes",
          "optional": "true"
        },
        "produces": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service produces (uses for output) such as application/xml or application/json This option will override what may be configured on a parent level",
          "title": "Produces",
          "optional": "true"
        },
        "bindingMode": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the binding mode to use. This option will override what may be configured on a parent level The default value is auto",
          "title": "Binding Mode",
          "optional": "true"
        },
        "skipBindingOnErrorCode": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to skip binding on output if there is a custom HTTP error code header. This allows to build custom error messages that do not bind to json / xml etc as success messages otherwise will do. This option will override what may be configured on a parent level",
          "title": "Skip Binding On Error Code",
          "optional": "true"
        },
        "enableCORS": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to enable CORS headers in the HTTP response. This option will override what may be configured on a parent level The default value is false.",
          "title": "Enable C O R S",
          "optional": "true"
        },
        "type": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from input to POJO for the incoming data This option will override what may be configured on a parent level",
          "title": "Type",
          "optional": "true"
        },
        "outType": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from POJO to output for the outgoing data This option will override what may be configured on a parent level",
          "title": "Out Type",
          "optional": "true"
        },
        "toOrRoute": {
          "kind": "element",
          "type": "object",
          "description": "To route from this REST service to a Camel endpoint or an inlined route",
          "title": "To Or Route",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "rest": {
      "type": "object",
      "title": "Rest",
      "group": "rest",
      "description": "Defines a rest service using the rest-dsl",
      "acceptInput": "false",
      "acceptOutput": "true",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "path": {
          "kind": "attribute",
          "type": "string",
          "description": "Path of the rest service such as /foo",
          "title": "Path",
          "optional": "true"
        },
        "consumes": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service consumes (accept as input) such as application/xml or application/json. This option will override what may be configured on a parent level",
          "title": "Consumes",
          "optional": "true"
        },
        "produces": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service produces (uses for output) such as application/xml or application/json This option will override what may be configured on a parent level",
          "title": "Produces",
          "optional": "true"
        },
        "bindingMode": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the binding mode to use. This option will override what may be configured on a parent level The default value is auto",
          "title": "Binding Mode",
          "optional": "true"
        },
        "skipBindingOnErrorCode": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to skip binding on output if there is a custom HTTP error code header. This allows to build custom error messages that do not bind to json / xml etc as success messages otherwise will do. This option will override what may be configured on a parent level",
          "title": "Skip Binding On Error Code",
          "optional": "true"
        },
        "enableCORS": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to enable CORS headers in the HTTP response. This option will override what may be configured on a parent level The default value is false.",
          "title": "Enable C O R S",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "restBinding": {
      "type": "object",
      "title": "Rest Binding",
      "group": "rest",
      "description": "To configure rest binding",
      "acceptInput": "true",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "true",
      "properties": {
        "consumes": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service consumes (accept as input) such as application/xml or application/json",
          "title": "Consumes",
          "optional": "true"
        },
        "produces": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service produces (uses for output) such as application/xml or application/json",
          "title": "Produces",
          "optional": "true"
        },
        "bindingMode": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the binding mode to use. The default value is auto",
          "title": "Binding Mode",
          "optional": "true"
        },
        "type": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from input to POJO for the incoming data",
          "title": "Type",
          "optional": "true"
        },
        "outType": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from POJO to output for the outgoing data",
          "title": "Out Type",
          "optional": "true"
        },
        "skipBindingOnErrorCode": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to skip binding on output if there is a custom HTTP error code header. This allows to build custom error messages that do not bind to json / xml etc as success messages otherwise will do.",
          "title": "Skip Binding On Error Code",
          "optional": "true"
        },
        "enableCORS": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to enable CORS headers in the HTTP response. The default value is false.",
          "title": "Enable C O R S",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "restConfiguration": {
      "type": "object",
      "title": "Rest Configuration",
      "group": "rest",
      "description": "To configure rest",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "component": {
          "kind": "attribute",
          "type": "string",
          "description": "The Camel Rest component to use for the REST transport such as restlet spark-rest. If no component has been explicit configured then Camel will lookup if there is a Camel component that integrates with the Rest DSL or if a org.apache.camel.spi.RestConsumerFactory is registered in the registry. If either one is found then that is being used.",
          "title": "Component",
          "optional": "true"
        },
        "scheme": {
          "kind": "attribute",
          "type": "string",
          "description": "The scheme to use for exposing the REST service. Usually http or https is supported. The default value is http",
          "title": "Scheme",
          "optional": "true"
        },
        "host": {
          "kind": "attribute",
          "type": "string",
          "description": "The hostname to use for exposing the REST service.",
          "title": "Host",
          "optional": "true"
        },
        "port": {
          "kind": "attribute",
          "type": "string",
          "description": "The port number to use for exposing the REST service. Notice if you use servlet component then the port number configured here does not apply as the port number in use is the actual port number the servlet component is using. eg if using Apache Tomcat its the tomcat http port if using Apache Karaf its the HTTP service in Karaf that uses port 8181 by default etc. Though in those situations setting the port number here allows tooling and JMX to know the port number so its recommended to set the port number to the number that the servlet engine uses.",
          "title": "Port",
          "optional": "true"
        },
        "contextPath": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets a leading context-path the REST services will be using. This can be used when using components such as SERVLET where the deployed web application is deployed using a context-path.",
          "title": "Context Path",
          "optional": "true"
        },
        "hostNameResolver": {
          "kind": "attribute",
          "type": "string",
          "description": "If no hostname has been explicit configured then this resolver is used to compute the hostname the REST service will be using.",
          "title": "Host Name Resolver",
          "optional": "true"
        },
        "bindingMode": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the binding mode to use. The default value is auto",
          "title": "Binding Mode",
          "optional": "true"
        },
        "skipBindingOnErrorCode": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to skip binding on output if there is a custom HTTP error code header. This allows to build custom error messages that do not bind to json / xml etc as success messages otherwise will do.",
          "title": "Skip Binding On Error Code",
          "optional": "true"
        },
        "enableCORS": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to enable CORS headers in the HTTP response. The default value is false.",
          "title": "Enable C O R S",
          "optional": "true"
        },
        "jsonDataFormat": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of specific json data format to use. By default json-jackson will be used. Important: This option is only for setting a custom name of the data format not to refer to an existing data format instance.",
          "title": "Json Data Format",
          "optional": "true"
        },
        "xmlDataFormat": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of specific XML data format to use. By default jaxb will be used. Important: This option is only for setting a custom name of the data format not to refer to an existing data format instance.",
          "title": "Xml Data Format",
          "optional": "true"
        },
        "componentProperty": {
          "kind": "element",
          "type": "array",
          "description": "Allows to configure as many additional properties for the rest component in use.",
          "title": "Component Property",
          "optional": "true"
        },
        "endpointProperty": {
          "kind": "element",
          "type": "array",
          "description": "Allows to configure as many additional properties for the rest endpoint in use.",
          "title": "Endpoint Property",
          "optional": "true"
        },
        "consumerProperty": {
          "kind": "element",
          "type": "array",
          "description": "Allows to configure as many additional properties for the rest consumer in use.",
          "title": "Consumer Property",
          "optional": "true"
        },
        "dataFormatProperty": {
          "kind": "element",
          "type": "array",
          "description": "Allows to configure as many additional properties for the data formats in use. For example set property prettyPrint to true to have json outputted in pretty mode. The properties can be prefixed to denote the option is only for either JSON or XML and for either the IN or the OUT. The prefixes are: json.in. json.out. xml.in. xml.out. For example a key with value xml.out.mustBeJAXBElement is only for the XML data format for the outgoing. A key without a prefix is a common key for all situations.",
          "title": "Data Format Property",
          "optional": "true"
        },
        "corsHeaders": {
          "kind": "element",
          "type": "array",
          "description": "Allows to configure custom CORS headers.",
          "title": "Cors Headers",
          "optional": "true"
        }
      }
    },
    "restProperty": {
      "type": "object",
      "title": "Rest Property",
      "group": "rest",
      "description": "A key value pair",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "key": {
          "kind": "attribute",
          "type": "string",
          "description": "Property key",
          "title": "Key",
          "optional": "false"
        },
        "value": {
          "kind": "attribute",
          "type": "string",
          "description": "Property value",
          "title": "Value",
          "optional": "false"
        }
      }
    },
    "rests": {
      "type": "object",
      "title": "Rests",
      "group": "rest",
      "description": "A series of rest services defined using the rest-dsl",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    },
    "verb": {
      "type": "object",
      "title": "Verb",
      "group": "rest",
      "description": "Rest command",
      "acceptInput": "false",
      "acceptOutput": "false",
      "nextSiblingAddedAsChild": "false",
      "properties": {
        "method": {
          "kind": "attribute",
          "type": "string",
          "description": "The HTTP verb such as GET or POST",
          "title": "Method",
          "optional": "true"
        },
        "uri": {
          "kind": "attribute",
          "type": "string",
          "description": "Uri template of this REST service such as /id.",
          "title": "Uri",
          "optional": "true"
        },
        "consumes": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service consumes (accept as input) such as application/xml or application/json. This option will override what may be configured on a parent level",
          "title": "Consumes",
          "optional": "true"
        },
        "produces": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the content type what the REST service produces (uses for output) such as application/xml or application/json This option will override what may be configured on a parent level",
          "title": "Produces",
          "optional": "true"
        },
        "bindingMode": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the binding mode to use. This option will override what may be configured on a parent level The default value is auto",
          "title": "Binding Mode",
          "optional": "true"
        },
        "skipBindingOnErrorCode": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to skip binding on output if there is a custom HTTP error code header. This allows to build custom error messages that do not bind to json / xml etc as success messages otherwise will do. This option will override what may be configured on a parent level",
          "title": "Skip Binding On Error Code",
          "optional": "true"
        },
        "enableCORS": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to enable CORS headers in the HTTP response. This option will override what may be configured on a parent level The default value is false.",
          "title": "Enable C O R S",
          "optional": "true"
        },
        "type": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from input to POJO for the incoming data This option will override what may be configured on a parent level",
          "title": "Type",
          "optional": "true"
        },
        "outType": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name to use for binding from POJO to output for the outgoing data This option will override what may be configured on a parent level",
          "title": "Out Type",
          "optional": "true"
        },
        "toOrRoute": {
          "kind": "element",
          "type": "object",
          "description": "To route from this REST service to a Camel endpoint or an inlined route",
          "title": "To Or Route",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "description": {
          "kind": "element",
          "type": "object",
          "description": "Sets the description of this node",
          "title": "Description",
          "optional": "true"
        }
      }
    }
  },
  "dataformats": {
    "avro": {
      "type": "object",
      "title": "Avro",
      "group": "dataformat,transformation",
      "description": "Avro data format",
      "properties": {
        "instanceClassName": {
          "kind": "attribute",
          "type": "string",
          "description": "Class name to use for marshal and unmarshalling",
          "title": "Instance Class Name",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "barcode": {
      "type": "object",
      "title": "Barcode",
      "group": "dataformat,transformation",
      "description": "Barcode data format",
      "properties": {
        "width": {
          "kind": "attribute",
          "type": "number",
          "description": "Width of the barcode",
          "title": "Width",
          "optional": "true"
        },
        "height": {
          "kind": "attribute",
          "type": "number",
          "description": "Height of the barcode",
          "title": "Height",
          "optional": "true"
        },
        "imageType": {
          "kind": "attribute",
          "type": "string",
          "description": "Image type of the barcode such as png",
          "title": "Image Type",
          "optional": "true"
        },
        "barcodeFormat": {
          "kind": "attribute",
          "type": "string",
          "description": "Barcode format such as QR-Code",
          "title": "Barcode Format",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "base64": {
      "type": "object",
      "title": "Base64",
      "group": "dataformat,transformation",
      "description": "Base64 data format",
      "properties": {
        "lineLength": {
          "kind": "attribute",
          "type": "number",
          "description": "To specific a maximum line length for the encoded data. By default 76 is used.",
          "title": "Line Length",
          "optional": "true"
        },
        "lineSeparator": {
          "kind": "attribute",
          "type": "string",
          "description": "The line separators to use. By default \r\n is used.",
          "title": "Line Separator",
          "optional": "true"
        },
        "urlSafe": {
          "kind": "attribute",
          "type": "bool",
          "description": "Instead of emitting '' and '/' we emit '-' and '_' respectively. urlSafe is only applied to encode operations. Decoding seamlessly handles both modes. Is by default false.",
          "title": "Url Safe",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "beanio": {
      "type": "object",
      "title": "Beanio",
      "group": "dataformat,transformation",
      "description": "BeanIO data format",
      "properties": {
        "mapping": {
          "kind": "attribute",
          "type": "string",
          "description": "The BeanIO mapping file. Is by default loaded from the classpath. You can prefix with file: http: or classpath: to denote from where to load the mapping file.",
          "title": "Mapping",
          "optional": "false"
        },
        "streamName": {
          "kind": "attribute",
          "type": "string",
          "description": "The name of the stream to use.",
          "title": "Stream Name",
          "optional": "false"
        },
        "ignoreUnidentifiedRecords": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to ignore unidentified records.",
          "title": "Ignore Unidentified Records",
          "optional": "true"
        },
        "ignoreUnexpectedRecords": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to ignore unexpected records.",
          "title": "Ignore Unexpected Records",
          "optional": "true"
        },
        "ignoreInvalidRecords": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to ignore invalid records.",
          "title": "Ignore Invalid Records",
          "optional": "true"
        },
        "encoding": {
          "kind": "attribute",
          "type": "string",
          "description": "The charset to use. Is by default the JVM platform default charset.",
          "title": "Encoding",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "bindy": {
      "type": "object",
      "title": "Bindy",
      "group": "dataformat,transformation",
      "description": "Bindy data format",
      "properties": {
        "type": {
          "kind": "attribute",
          "type": "string",
          "description": "Whether to use csv fixed or key value pairs mode.",
          "title": "Type",
          "optional": "false"
        },
        "packages": {
          "kind": "attribute",
          "type": "array",
          "description": "The java package names to scan for model classes.",
          "title": "Packages",
          "optional": "true"
        },
        "classType": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of model class to use.",
          "title": "Class Type",
          "optional": "true"
        },
        "locale": {
          "kind": "attribute",
          "type": "string",
          "description": "To configure a default locale to use such as us for united states. To use the JVM platform default locale then use the name default",
          "title": "Locale",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "castor": {
      "type": "object",
      "title": "Castor",
      "group": "dataformat,transformation",
      "description": "Castor data format",
      "properties": {
        "mappingFile": {
          "kind": "attribute",
          "type": "string",
          "description": "Path to a Castor mapping file to load from the classpath.",
          "title": "Mapping File",
          "optional": "true"
        },
        "validation": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether validation is turned on or off. Is by default true.",
          "title": "Validation",
          "optional": "true"
        },
        "encoding": {
          "kind": "attribute",
          "type": "string",
          "description": "Encoding to use when marshalling an Object to XML. Is by default UTF-8",
          "title": "Encoding",
          "optional": "true"
        },
        "packages": {
          "kind": "attribute",
          "type": "array",
          "description": "Add additional packages to Castor XmlContext",
          "title": "Packages",
          "optional": "true"
        },
        "classes": {
          "kind": "attribute",
          "type": "array",
          "description": "Add additional class names to Castor XmlContext",
          "title": "Classes",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "crypto": {
      "type": "object",
      "title": "Crypto",
      "group": "dataformat,transformation",
      "description": "Crypto data format",
      "properties": {
        "algorithm": {
          "kind": "attribute",
          "type": "string",
          "description": "The JCE algorithm name indicating the cryptographic algorithm that will be used. Is by default DES/CBC/PKCS5Padding.",
          "title": "Algorithm",
          "optional": "true"
        },
        "cryptoProvider": {
          "kind": "attribute",
          "type": "string",
          "description": "The name of the JCE Security Provider that should be used.",
          "title": "Crypto Provider",
          "optional": "true"
        },
        "keyRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to the secret key to lookup from the register to use.",
          "title": "Key Ref",
          "optional": "true"
        },
        "initVectorRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to a byte array containing the Initialization Vector that will be used to initialize the Cipher.",
          "title": "Init Vector Ref",
          "optional": "true"
        },
        "algorithmParameterRef": {
          "kind": "attribute",
          "type": "string",
          "description": "A JCE AlgorithmParameterSpec used to initialize the Cipher. Will lookup the type using the given name as a java.security.spec.AlgorithmParameterSpec type.",
          "title": "Algorithm Parameter Ref",
          "optional": "true"
        },
        "buffersize": {
          "kind": "attribute",
          "type": "number",
          "description": "The size of the buffer used in the signature process.",
          "title": "Buffersize",
          "optional": "true"
        },
        "macAlgorithm": {
          "kind": "attribute",
          "type": "string",
          "description": "The JCE algorithm name indicating the Message Authentication algorithm.",
          "title": "Mac Algorithm",
          "optional": "true"
        },
        "shouldAppendHMAC": {
          "kind": "attribute",
          "type": "bool",
          "description": "Flag indicating that a Message Authentication Code should be calculated and appended to the encrypted data.",
          "title": "Should Append H M A C",
          "optional": "true"
        },
        "inline": {
          "kind": "attribute",
          "type": "bool",
          "description": "Flag indicating that the configured IV should be inlined into the encrypted data stream. Is by default false.",
          "title": "Inline",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "csv": {
      "type": "object",
      "title": "Csv",
      "group": "dataformat,transformation",
      "description": "CSV data format",
      "properties": {
        "formatRef": {
          "kind": "attribute",
          "type": "string",
          "description": "The reference format to use it will be updated with the other format options the default value is CSVFormat.DEFAULT",
          "title": "Format Ref",
          "optional": "true"
        },
        "formatName": {
          "kind": "attribute",
          "type": "string",
          "description": "The name of the format to use the default value is CSVFormat.DEFAULT",
          "title": "Format Name",
          "optional": "true"
        },
        "commentMarkerDisabled": {
          "kind": "attribute",
          "type": "bool",
          "description": "Disables the comment marker of the reference format.",
          "title": "Comment Marker Disabled",
          "optional": "true"
        },
        "commentMarker": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the comment marker of the reference format.",
          "title": "Comment Marker",
          "optional": "true"
        },
        "delimiter": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the delimiter to use. The default value is (comma)",
          "title": "Delimiter",
          "optional": "true"
        },
        "escapeDisabled": {
          "kind": "attribute",
          "type": "bool",
          "description": "Use for disabling using escape character",
          "title": "Escape Disabled",
          "optional": "true"
        },
        "escape": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the escape character to use",
          "title": "Escape",
          "optional": "true"
        },
        "headerDisabled": {
          "kind": "attribute",
          "type": "bool",
          "description": "Use for disabling headers",
          "title": "Header Disabled",
          "optional": "true"
        },
        "header": {
          "kind": "element",
          "type": "array",
          "description": "To configure the CSV headers",
          "title": "Header",
          "optional": "true"
        },
        "allowMissingColumnNames": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to allow missing column names.",
          "title": "Allow Missing Column Names",
          "optional": "true"
        },
        "ignoreEmptyLines": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to ignore empty lines.",
          "title": "Ignore Empty Lines",
          "optional": "true"
        },
        "ignoreSurroundingSpaces": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to ignore surrounding spaces",
          "title": "Ignore Surrounding Spaces",
          "optional": "true"
        },
        "nullStringDisabled": {
          "kind": "attribute",
          "type": "bool",
          "description": "Used to disable null strings",
          "title": "Null String Disabled",
          "optional": "true"
        },
        "nullString": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the null string",
          "title": "Null String",
          "optional": "true"
        },
        "quoteDisabled": {
          "kind": "attribute",
          "type": "bool",
          "description": "Used to disable quotes",
          "title": "Quote Disabled",
          "optional": "true"
        },
        "quote": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the quote which by default is",
          "title": "Quote",
          "optional": "true"
        },
        "recordSeparatorDisabled": {
          "kind": "attribute",
          "type": "string",
          "description": "Used for disabling record separator",
          "title": "Record Separator Disabled",
          "optional": "true"
        },
        "recordSeparator": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the record separator (aka new line) which by default is \r\n (CRLF)",
          "title": "Record Separator",
          "optional": "true"
        },
        "skipHeaderRecord": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to skip the header record in the output",
          "title": "Skip Header Record",
          "optional": "true"
        },
        "lazyLoad": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether the unmarshalling should produce an iterator that reads the lines on the fly or if all the lines must be read at one.",
          "title": "Lazy Load",
          "optional": "true"
        },
        "useMaps": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether the unmarshalling should produce maps for the lines values instead of lists. It requires to have header (either defined or collected).",
          "title": "Use Maps",
          "optional": "true"
        },
        "recordConverterRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to a custom CsvRecordConverter to lookup from the registry to use.",
          "title": "Record Converter Ref",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "customDataFormat": {
      "type": "object",
      "title": "Custom Data Format",
      "group": "dataformat,transformation",
      "description": "Custom data format",
      "properties": {
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Reference to the custom org.apache.camel.spi.DataFormat to lookup from the Camel registry.",
          "title": "Ref",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "dataFormats": {
      "type": "object",
      "title": "Data Formats",
      "group": "dataformat,transformation",
      "description": "To configure data formats",
      "properties": {
        "dataFormats": {
          "kind": "element",
          "type": "array",
          "description": "A list holding the configured data formats",
          "title": "Data Formats",
          "optional": "false"
        }
      }
    },
    "flatpack": {
      "type": "object",
      "title": "Flatpack",
      "group": "dataformat,transformation",
      "description": "Flatpack data format",
      "properties": {
        "parserFactoryRef": {
          "kind": "attribute",
          "type": "string",
          "description": "References to a custom parser factory to lookup in the registry",
          "title": "Parser Factory Ref",
          "optional": "true"
        },
        "definition": {
          "kind": "attribute",
          "type": "string",
          "description": "The flatpack pzmap configuration file. Can be omitted in simpler situations but its preferred to use the pzmap.",
          "title": "Definition",
          "optional": "true"
        },
        "fixed": {
          "kind": "attribute",
          "type": "bool",
          "description": "Delimited or fixed. Is by default false = delimited",
          "title": "Fixed",
          "optional": "true"
        },
        "ignoreFirstRecord": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether the first line is ignored for delimited files (for the column headers). Is by default true.",
          "title": "Ignore First Record",
          "optional": "true"
        },
        "textQualifier": {
          "kind": "attribute",
          "type": "string",
          "description": "If the text is qualified with a char such as The default value is",
          "title": "Text Qualifier",
          "optional": "true"
        },
        "delimiter": {
          "kind": "attribute",
          "type": "string",
          "description": "The delimiter char (could be ; or similar) The default value is",
          "title": "Delimiter",
          "optional": "true"
        },
        "allowShortLines": {
          "kind": "attribute",
          "type": "bool",
          "description": "Allows for lines to be shorter than expected and ignores the extra characters",
          "title": "Allow Short Lines",
          "optional": "true"
        },
        "ignoreExtraColumns": {
          "kind": "attribute",
          "type": "bool",
          "description": "Allows for lines to be longer than expected and ignores the extra characters.",
          "title": "Ignore Extra Columns",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "gzip": {
      "type": "object",
      "title": "Gzip",
      "group": "dataformat,transformation",
      "description": "GZip data format",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "hl7": {
      "type": "object",
      "title": "Hl7",
      "group": "dataformat,transformation,hl7",
      "description": "HL7 data format",
      "properties": {
        "validate": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to validate the HL7 message Is by default true.",
          "title": "Validate",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "ical": {
      "type": "object",
      "title": "Ical",
      "group": "dataformat,transformation",
      "description": "iCal data format",
      "properties": {
        "validating": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to validate.",
          "title": "Validating",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "jaxb": {
      "type": "object",
      "title": "Jaxb",
      "group": "dataformat,transformation",
      "description": "JAXB data format",
      "properties": {
        "contextPath": {
          "kind": "attribute",
          "type": "string",
          "description": "Package name where your JAXB classes are located.",
          "title": "Context Path",
          "optional": "false"
        },
        "schema": {
          "kind": "attribute",
          "type": "string",
          "description": "To validate against an existing schema. Your can use the prefix classpath: file: or http: to specify how the resource should by resolved. You can separate multiple schema files by using the '' character.",
          "title": "Schema",
          "optional": "true"
        },
        "prettyPrint": {
          "kind": "attribute",
          "type": "bool",
          "description": "To enable pretty printing output nicely formatted. Is by default false.",
          "title": "Pretty Print",
          "optional": "true"
        },
        "ignoreJAXBElement": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to ignore JAXBElement elements - only needed to be set to false in very special use-cases.",
          "title": "Ignore J A X B Element",
          "optional": "true"
        },
        "mustBeJAXBElement": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether marhsalling must be java objects with JAXB annotations. And if not then it fails. This option can be set to false to relax that such as when the data is already in XML format.",
          "title": "Must Be J A X B Element",
          "optional": "true"
        },
        "filterNonXmlChars": {
          "kind": "attribute",
          "type": "bool",
          "description": "To ignore non xml characheters and replace them with an empty space.",
          "title": "Filter Non Xml Chars",
          "optional": "true"
        },
        "encoding": {
          "kind": "attribute",
          "type": "string",
          "description": "To overrule and use a specific encoding",
          "title": "Encoding",
          "optional": "true"
        },
        "fragment": {
          "kind": "attribute",
          "type": "bool",
          "description": "To turn on marshalling XML fragment trees. By default JAXB looks for XmlRootElement annotation on given class to operate on whole XML tree. This is useful but not always - sometimes generated code does not have XmlRootElement annotation sometimes you need unmarshall only part of tree. In that case you can use partial unmarshalling. To enable this behaviours you need set property partClass. Camel will pass this class to JAXB's unmarshaler.",
          "title": "Fragment",
          "optional": "true"
        },
        "partClass": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of class used for fragment parsing. See more details at the fragment option.",
          "title": "Part Class",
          "optional": "true"
        },
        "partNamespace": {
          "kind": "attribute",
          "type": "string",
          "description": "XML namespace to use for fragment parsing. See more details at the fragment option.",
          "title": "Part Namespace",
          "optional": "true"
        },
        "namespacePrefixRef": {
          "kind": "attribute",
          "type": "string",
          "description": "When marshalling using JAXB or SOAP then the JAXB implementation will automatic assign namespace prefixes such as ns2 ns3 ns4 etc. To control this mapping Camel allows you to refer to a map which contains the desired mapping.",
          "title": "Namespace Prefix Ref",
          "optional": "true"
        },
        "xmlStreamWriterWrapper": {
          "kind": "attribute",
          "type": "string",
          "description": "To use a custom xml stream writer.",
          "title": "Xml Stream Writer Wrapper",
          "optional": "true"
        },
        "schemaLocation": {
          "kind": "attribute",
          "type": "string",
          "description": "To define the location of the schema",
          "title": "Schema Location",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "jibx": {
      "type": "object",
      "title": "Jibx",
      "group": "dataformat,transformation",
      "description": "JiBX data format",
      "properties": {
        "unmarshallClass": {
          "kind": "attribute",
          "type": "string",
          "description": "Class name to use when unmarshalling from XML to Java.",
          "title": "Unmarshall Class",
          "optional": "true"
        },
        "bindingName": {
          "kind": "attribute",
          "type": "string",
          "description": "To use a custom binding factory",
          "title": "Binding Name",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "json": {
      "type": "object",
      "title": "Json",
      "group": "dataformat,transformation",
      "description": "Json data format",
      "properties": {
        "prettyPrint": {
          "kind": "attribute",
          "type": "bool",
          "description": "To enable pretty printing output nicely formatted. Is by default false.",
          "title": "Pretty Print",
          "optional": "true"
        },
        "library": {
          "kind": "attribute",
          "type": "string",
          "description": "Which json library to use such. Is by default xstream",
          "title": "Library",
          "optional": "true"
        },
        "unmarshalTypeName": {
          "kind": "attribute",
          "type": "string",
          "description": "Class name of the java type to use when unarmshalling",
          "title": "Unmarshal Type Name",
          "optional": "true"
        },
        "jsonView": {
          "kind": "attribute",
          "type": "string",
          "description": "When marshalling a POJO to JSON you might want to exclude certain fields from the JSON output. With Jackson you can use JSON views to accomplish this. This option is to refer to the class which has JsonView annotations",
          "title": "Json View",
          "optional": "true"
        },
        "include": {
          "kind": "attribute",
          "type": "string",
          "description": "If you want to marshal a pojo to JSON and the pojo has some fields with null values. And you want to skip these null values you can set this option to NOT_NULL",
          "title": "Include",
          "optional": "true"
        },
        "allowJmsType": {
          "kind": "attribute",
          "type": "bool",
          "description": "Used for JMS users to allow the JMSType header from the JMS spec to specify a FQN classname to use to unmarshal to.",
          "title": "Allow Jms Type",
          "optional": "true"
        },
        "collectionTypeName": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to a custom collection type to lookup in the registry to use. This option should rarely be used but allows to use different collection types than java.util.Collection based as default.",
          "title": "Collection Type Name",
          "optional": "true"
        },
        "useList": {
          "kind": "attribute",
          "type": "bool",
          "description": "To unarmshal to a List of Map or a List of Pojo.",
          "title": "Use List",
          "optional": "true"
        },
        "enableJaxbAnnotationModule": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to enable the JAXB annotations module when using jackson. When enabled then JAXB annotations can be used by Jackson.",
          "title": "Enable Jaxb Annotation Module",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "pgp": {
      "type": "object",
      "title": "Pgp",
      "group": "dataformat,transformation",
      "description": "PGP data format",
      "properties": {
        "keyUserid": {
          "kind": "attribute",
          "type": "string",
          "description": "The user ID of the key in the PGP keyring used during encryption. Can also be only a part of a user ID. For example if the user ID is Test User then you can use the part Test User or to address the user ID.",
          "title": "Key Userid",
          "optional": "true"
        },
        "signatureKeyUserid": {
          "kind": "attribute",
          "type": "string",
          "description": "User ID of the key in the PGP keyring used for signing (during encryption) or signature verification (during decryption). During the signature verification process the specified User ID restricts the public keys from the public keyring which can be used for the verification. If no User ID is specified for the signature verficiation then any public key in the public keyring can be used for the verification. Can also be only a part of a user ID. For example if the user ID is Test User then you can use the part Test User or to address the User ID.",
          "title": "Signature Key Userid",
          "optional": "true"
        },
        "password": {
          "kind": "attribute",
          "type": "string",
          "description": "Password used when opening the private key (not used for encryption).",
          "title": "Password",
          "optional": "true"
        },
        "signaturePassword": {
          "kind": "attribute",
          "type": "string",
          "description": "Password used when opening the private key used for signing (during encryption).",
          "title": "Signature Password",
          "optional": "true"
        },
        "keyFileName": {
          "kind": "attribute",
          "type": "string",
          "description": "Filename of the keyring; must be accessible as a classpath resource (but you can specify a location in the file system by using the file: prefix).",
          "title": "Key File Name",
          "optional": "true"
        },
        "signatureKeyFileName": {
          "kind": "attribute",
          "type": "string",
          "description": "Filename of the keyring to use for signing (during encryption) or for signature verification (during decryption); must be accessible as a classpath resource (but you can specify a location in the file system by using the file: prefix).",
          "title": "Signature Key File Name",
          "optional": "true"
        },
        "signatureKeyRing": {
          "kind": "attribute",
          "type": "string",
          "description": "Keyring used for signing/verifying as byte array. You can not set the signatureKeyFileName and signatureKeyRing at the same time.",
          "title": "Signature Key Ring",
          "optional": "true"
        },
        "armored": {
          "kind": "attribute",
          "type": "bool",
          "description": "This option will cause PGP to base64 encode the encrypted text making it available for copy/paste etc.",
          "title": "Armored",
          "optional": "true"
        },
        "integrity": {
          "kind": "attribute",
          "type": "bool",
          "description": "Adds an integrity check/sign into the encryption file. The default value is true.",
          "title": "Integrity",
          "optional": "true"
        },
        "provider": {
          "kind": "attribute",
          "type": "string",
          "description": "Java Cryptography Extension (JCE) provider default is Bouncy Castle (BC). Alternatively you can use for example the IAIK JCE provider; in this case the provider must be registered beforehand and the Bouncy Castle provider must not be registered beforehand. The Sun JCE provider does not work.",
          "title": "Provider",
          "optional": "true"
        },
        "algorithm": {
          "kind": "attribute",
          "type": "number",
          "description": "Symmetric key encryption algorithm; possible values are defined in org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags; for example 2 (= TRIPLE DES) 3 (= CAST5) 4 (= BLOWFISH) 6 (= DES) 7 (= AES_128). Only relevant for encrypting.",
          "title": "Algorithm",
          "optional": "true"
        },
        "compressionAlgorithm": {
          "kind": "attribute",
          "type": "number",
          "description": "Compression algorithm; possible values are defined in org.bouncycastle.bcpg.CompressionAlgorithmTags; for example 0 (= UNCOMPRESSED) 1 (= ZIP) 2 (= ZLIB) 3 (= BZIP2). Only relevant for encrypting.",
          "title": "Compression Algorithm",
          "optional": "true"
        },
        "hashAlgorithm": {
          "kind": "attribute",
          "type": "number",
          "description": "Signature hash algorithm; possible values are defined in org.bouncycastle.bcpg.HashAlgorithmTags; for example 2 (= SHA1) 8 (= SHA256) 9 (= SHA384) 10 (= SHA512) 11 (=SHA224). Only relevant for signing.",
          "title": "Hash Algorithm",
          "optional": "true"
        },
        "signatureVerificationOption": {
          "kind": "attribute",
          "type": "string",
          "description": "Controls the behavior for verifying the signature during unmarshaling. There are 4 values possible: optional: The PGP message may or may not contain signatures; if it does contain signatures then a signature verification is executed. required: The PGP message must contain at least one signature; if this is not the case an exception (PGPException) is thrown. A signature verification is executed. ignore: Contained signatures in the PGP message are ignored; no signature verification is executed. no_signature_allowed: The PGP message must not contain a signature; otherwise an exception (PGPException) is thrown.",
          "title": "Signature Verification Option",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "protobuf": {
      "type": "object",
      "title": "Protobuf",
      "group": "dataformat,transformation",
      "description": "Google protobuf data format",
      "properties": {
        "instanceClass": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of class to use when unarmshalling",
          "title": "Instance Class",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "rss": {
      "type": "object",
      "title": "Rss",
      "group": "dataformat,transformation",
      "description": "RSS data format",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "secureXML": {
      "type": "object",
      "title": "Secure X M L",
      "group": "dataformat,transformation",
      "description": "xml-security data format",
      "properties": {
        "xmlCipherAlgorithm": {
          "kind": "attribute",
          "type": "string",
          "description": "The cipher algorithm to be used for encryption/decryption of the XML message content. The available choices are: XMLCipher.TRIPLEDES XMLCipher.AES_128 XMLCipher.AES_128_GCM XMLCipher.AES_192 XMLCipher.AES_192_GCM XMLCipher.AES_256 XMLCipher.AES_256_GCM XMLCipher.SEED_128 XMLCipher.CAMELLIA_128 XMLCipher.CAMELLIA_192 XMLCipher.CAMELLIA_256 The default value is MLCipher.TRIPLEDES",
          "title": "Xml Cipher Algorithm",
          "optional": "true"
        },
        "passPhrase": {
          "kind": "attribute",
          "type": "string",
          "description": "A String used as passPhrase to encrypt/decrypt content. The passPhrase has to be provided. If no passPhrase is specified a default passPhrase is used. The passPhrase needs to be put together in conjunction with the appropriate encryption algorithm. For example using TRIPLEDES the passPhase can be a Only another 24 Byte key",
          "title": "Pass Phrase",
          "optional": "true"
        },
        "secureTag": {
          "kind": "attribute",
          "type": "string",
          "description": "The XPath reference to the XML Element selected for encryption/decryption. If no tag is specified the entire payload is encrypted/decrypted.",
          "title": "Secure Tag",
          "optional": "true"
        },
        "secureTagContents": {
          "kind": "attribute",
          "type": "bool",
          "description": "A boolean value to specify whether the XML Element is to be encrypted or the contents of the XML Element false = Element Level true = Element Content Level",
          "title": "Secure Tag Contents",
          "optional": "true"
        },
        "keyCipherAlgorithm": {
          "kind": "attribute",
          "type": "string",
          "description": "The cipher algorithm to be used for encryption/decryption of the asymmetric key. The available choices are: XMLCipher.RSA_v1dot5 XMLCipher.RSA_OAEP XMLCipher.RSA_OAEP_11 The default value is XMLCipher.RSA_OAEP",
          "title": "Key Cipher Algorithm",
          "optional": "true"
        },
        "recipientKeyAlias": {
          "kind": "attribute",
          "type": "string",
          "description": "The key alias to be used when retrieving the recipient's public or private key from a KeyStore when performing asymmetric key encryption or decryption.",
          "title": "Recipient Key Alias",
          "optional": "true"
        },
        "keyOrTrustStoreParametersId": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to a KeyStore instance to lookup in the registry which is used for configuration options for creating and loading a KeyStore instance that represents the sender's trustStore or recipient's keyStore.",
          "title": "Key Or Trust Store Parameters Id",
          "optional": "true"
        },
        "keyPassword": {
          "kind": "attribute",
          "type": "string",
          "description": "The password to be used for retrieving the private key from the KeyStore. This key is used for asymmetric decryption.",
          "title": "Key Password",
          "optional": "true"
        },
        "digestAlgorithm": {
          "kind": "attribute",
          "type": "string",
          "description": "The digest algorithm to use with the RSA OAEP algorithm. The available choices are: XMLCipher.SHA1 XMLCipher.SHA256 XMLCipher.SHA512 The default value is XMLCipher.SHA1",
          "title": "Digest Algorithm",
          "optional": "true"
        },
        "mgfAlgorithm": {
          "kind": "attribute",
          "type": "string",
          "description": "The MGF Algorithm to use with the RSA OAEP algorithm. The available choices are: EncryptionConstants.MGF1_SHA1 EncryptionConstants.MGF1_SHA256 EncryptionConstants.MGF1_SHA512 The default value is EncryptionConstants.MGF1_SHA1",
          "title": "Mgf Algorithm",
          "optional": "true"
        },
        "addKeyValueForEncryptedKey": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to add the public key used to encrypt the session key as a KeyValue in the EncryptedKey structure or not.",
          "title": "Add Key Value For Encrypted Key",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "serialization": {
      "type": "object",
      "title": "Serialization",
      "group": "dataformat,transformation",
      "description": "Java Object Serialization data format",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "soapjaxb": {
      "type": "object",
      "title": "Soapjaxb",
      "group": "dataformat,transformation",
      "description": "SOAP data format",
      "properties": {
        "contextPath": {
          "kind": "attribute",
          "type": "string",
          "description": "Package name where your JAXB classes are located.",
          "title": "Context Path",
          "optional": "false"
        },
        "encoding": {
          "kind": "attribute",
          "type": "string",
          "description": "To overrule and use a specific encoding",
          "title": "Encoding",
          "optional": "true"
        },
        "elementNameStrategyRef": {
          "kind": "attribute",
          "type": "string",
          "description": "Refers to an element strategy to lookup from the registry. An element name strategy is used for two purposes. The first is to find a xml element name for a given object and soap action when marshaling the object into a SOAP message. The second is to find an Exception class for a given soap fault name. The following three element strategy class name is provided out of the box. QNameStrategy - Uses a fixed qName that is configured on instantiation. Exception lookup is not supported TypeNameStrategy - Uses the name and namespace from the XMLType annotation of the given type. If no namespace is set then package-info is used. Exception lookup is not supported ServiceInterfaceStrategy - Uses information from a webservice interface to determine the type name and to find the exception class for a SOAP fault All three classes is located in the package name org.apache.camel.dataformat.soap.name If you have generated the web service stub code with cxf-codegen or a similar tool then you probably will want to use the ServiceInterfaceStrategy. In the case you have no annotated service interface you should use QNameStrategy or TypeNameStrategy.",
          "title": "Element Name Strategy Ref",
          "optional": "true"
        },
        "version": {
          "kind": "attribute",
          "type": "string",
          "description": "SOAP version should either be 1.1 or 1.2. Is by default 1.1",
          "title": "Version",
          "optional": "true"
        },
        "namespacePrefixRef": {
          "kind": "attribute",
          "type": "string",
          "description": "When marshalling using JAXB or SOAP then the JAXB implementation will automatic assign namespace prefixes such as ns2 ns3 ns4 etc. To control this mapping Camel allows you to refer to a map which contains the desired mapping.",
          "title": "Namespace Prefix Ref",
          "optional": "true"
        },
        "schema": {
          "kind": "attribute",
          "type": "string",
          "description": "To validate against an existing schema. Your can use the prefix classpath: file: or http: to specify how the resource should by resolved. You can separate multiple schema files by using the '' character.",
          "title": "Schema",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "string": {
      "type": "object",
      "title": "String",
      "group": "dataformat,transformation",
      "description": "Represents the String (text based) DataFormat",
      "properties": {
        "charset": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets an encoding to use. Will by default use the JVM platform default charset.",
          "title": "Charset",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "syslog": {
      "type": "object",
      "title": "Syslog",
      "group": "dataformat,transformation",
      "description": "Syslog data format",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "tidyMarkup": {
      "type": "object",
      "title": "Tidy Markup",
      "group": "dataformat,transformation",
      "description": "Tidymark (wellformed HTML) data format",
      "properties": {
        "dataObjectType": {
          "kind": "attribute",
          "type": "string",
          "description": "What data type to unmarshal as can either be org.w3c.dom.Node or java.lang.String. Is by default org.w3c.dom.Node",
          "title": "Data Object Type",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "univocity-csv": {
      "type": "object",
      "title": "Univocity-csv",
      "group": "dataformat,transformation",
      "description": "UniVocity CSV data format",
      "properties": {
        "quoteAllFields": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not all values must be quoted when writing them. The default value is false",
          "title": "Quote All Fields",
          "optional": "true"
        },
        "quote": {
          "kind": "attribute",
          "type": "string",
          "description": "The quote symbol. The default value is",
          "title": "Quote",
          "optional": "true"
        },
        "quoteEscape": {
          "kind": "attribute",
          "type": "string",
          "description": "The quote escape symbol The default value is",
          "title": "Quote Escape",
          "optional": "true"
        },
        "delimiter": {
          "kind": "attribute",
          "type": "string",
          "description": "The delimiter of values The default value is",
          "title": "Delimiter",
          "optional": "true"
        },
        "nullValue": {
          "kind": "attribute",
          "type": "string",
          "description": "The string representation of a null value. The default value is null",
          "title": "Null Value",
          "optional": "true"
        },
        "skipEmptyLines": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the empty lines must be ignored. The default value is true",
          "title": "Skip Empty Lines",
          "optional": "true"
        },
        "ignoreTrailingWhitespaces": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the trailing white spaces must ignored. The default value is true",
          "title": "Ignore Trailing Whitespaces",
          "optional": "true"
        },
        "ignoreLeadingWhitespaces": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the leading white spaces must be ignored. The default value is true",
          "title": "Ignore Leading Whitespaces",
          "optional": "true"
        },
        "headersDisabled": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the headers are disabled. When defined this option explicitly sets the headers as null which indicates that there is no header. The default value is false",
          "title": "Headers Disabled",
          "optional": "true"
        },
        "headerExtractionEnabled": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the header must be read in the first line of the test document The default value is false",
          "title": "Header Extraction Enabled",
          "optional": "true"
        },
        "numberOfRecordsToRead": {
          "kind": "attribute",
          "type": "number",
          "description": "The maximum number of record to read.",
          "title": "Number Of Records To Read",
          "optional": "true"
        },
        "emptyValue": {
          "kind": "attribute",
          "type": "string",
          "description": "The String representation of an empty value",
          "title": "Empty Value",
          "optional": "true"
        },
        "lineSeparator": {
          "kind": "attribute",
          "type": "string",
          "description": "The line separator of the files The default value is to use the JVM platform line separator",
          "title": "Line Separator",
          "optional": "true"
        },
        "normalizedLineSeparator": {
          "kind": "attribute",
          "type": "string",
          "description": "The normalized line separator of the files The default value is \n",
          "title": "Normalized Line Separator",
          "optional": "true"
        },
        "comment": {
          "kind": "attribute",
          "type": "string",
          "description": "The comment symbol. The default value is",
          "title": "Comment",
          "optional": "true"
        },
        "lazyLoad": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether the unmarshalling should produce an iterator that reads the lines on the fly or if all the lines must be read at one. The default value is false",
          "title": "Lazy Load",
          "optional": "true"
        },
        "asMap": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether the unmarshalling should produce maps for the lines values instead of lists. It requires to have header (either defined or collected). The default value is false",
          "title": "As Map",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "univocity-fixed": {
      "type": "object",
      "title": "Univocity-fixed",
      "group": "dataformat,transformation",
      "description": "UniVocity fixed-width data format",
      "properties": {
        "skipTrailingCharsUntilNewline": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the trailing characters until new line must be ignored. The default value is false",
          "title": "Skip Trailing Chars Until Newline",
          "optional": "true"
        },
        "recordEndsOnNewline": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the record ends on new line. The default value is false",
          "title": "Record Ends On Newline",
          "optional": "true"
        },
        "padding": {
          "kind": "attribute",
          "type": "string",
          "description": "The padding character. The default value is a space",
          "title": "Padding",
          "optional": "true"
        },
        "nullValue": {
          "kind": "attribute",
          "type": "string",
          "description": "The string representation of a null value. The default value is null",
          "title": "Null Value",
          "optional": "true"
        },
        "skipEmptyLines": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the empty lines must be ignored. The default value is true",
          "title": "Skip Empty Lines",
          "optional": "true"
        },
        "ignoreTrailingWhitespaces": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the trailing white spaces must ignored. The default value is true",
          "title": "Ignore Trailing Whitespaces",
          "optional": "true"
        },
        "ignoreLeadingWhitespaces": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the leading white spaces must be ignored. The default value is true",
          "title": "Ignore Leading Whitespaces",
          "optional": "true"
        },
        "headersDisabled": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the headers are disabled. When defined this option explicitly sets the headers as null which indicates that there is no header. The default value is false",
          "title": "Headers Disabled",
          "optional": "true"
        },
        "headerExtractionEnabled": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the header must be read in the first line of the test document The default value is false",
          "title": "Header Extraction Enabled",
          "optional": "true"
        },
        "numberOfRecordsToRead": {
          "kind": "attribute",
          "type": "number",
          "description": "The maximum number of record to read.",
          "title": "Number Of Records To Read",
          "optional": "true"
        },
        "emptyValue": {
          "kind": "attribute",
          "type": "string",
          "description": "The String representation of an empty value",
          "title": "Empty Value",
          "optional": "true"
        },
        "lineSeparator": {
          "kind": "attribute",
          "type": "string",
          "description": "The line separator of the files The default value is to use the JVM platform line separator",
          "title": "Line Separator",
          "optional": "true"
        },
        "normalizedLineSeparator": {
          "kind": "attribute",
          "type": "string",
          "description": "The normalized line separator of the files The default value is \n",
          "title": "Normalized Line Separator",
          "optional": "true"
        },
        "comment": {
          "kind": "attribute",
          "type": "string",
          "description": "The comment symbol. The default value is",
          "title": "Comment",
          "optional": "true"
        },
        "lazyLoad": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether the unmarshalling should produce an iterator that reads the lines on the fly or if all the lines must be read at one. The default value is false",
          "title": "Lazy Load",
          "optional": "true"
        },
        "asMap": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether the unmarshalling should produce maps for the lines values instead of lists. It requires to have header (either defined or collected). The default value is false",
          "title": "As Map",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "univocity-header": {
      "type": "object",
      "title": "Univocity-header",
      "group": "dataformat,transformation",
      "description": "To configure headers for UniVocity data formats.",
      "properties": {
        "name": {
          "kind": "value",
          "type": "string",
          "description": "Header name",
          "title": "Name",
          "optional": "false"
        },
        "length": {
          "kind": "attribute",
          "type": "number",
          "description": "Header length",
          "title": "Length",
          "optional": "true"
        }
      }
    },
    "univocity-tsv": {
      "type": "object",
      "title": "Univocity-tsv",
      "group": "dataformat,transformation",
      "description": "UniVocity TSV data format",
      "properties": {
        "escapeChar": {
          "kind": "attribute",
          "type": "string",
          "description": "The escape character.",
          "title": "Escape Char",
          "optional": "true"
        },
        "nullValue": {
          "kind": "attribute",
          "type": "string",
          "description": "The string representation of a null value. The default value is null",
          "title": "Null Value",
          "optional": "true"
        },
        "skipEmptyLines": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the empty lines must be ignored. The default value is true",
          "title": "Skip Empty Lines",
          "optional": "true"
        },
        "ignoreTrailingWhitespaces": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the trailing white spaces must ignored. The default value is true",
          "title": "Ignore Trailing Whitespaces",
          "optional": "true"
        },
        "ignoreLeadingWhitespaces": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the leading white spaces must be ignored. The default value is true",
          "title": "Ignore Leading Whitespaces",
          "optional": "true"
        },
        "headersDisabled": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the headers are disabled. When defined this option explicitly sets the headers as null which indicates that there is no header. The default value is false",
          "title": "Headers Disabled",
          "optional": "true"
        },
        "headerExtractionEnabled": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether or not the header must be read in the first line of the test document The default value is false",
          "title": "Header Extraction Enabled",
          "optional": "true"
        },
        "numberOfRecordsToRead": {
          "kind": "attribute",
          "type": "number",
          "description": "The maximum number of record to read.",
          "title": "Number Of Records To Read",
          "optional": "true"
        },
        "emptyValue": {
          "kind": "attribute",
          "type": "string",
          "description": "The String representation of an empty value",
          "title": "Empty Value",
          "optional": "true"
        },
        "lineSeparator": {
          "kind": "attribute",
          "type": "string",
          "description": "The line separator of the files The default value is to use the JVM platform line separator",
          "title": "Line Separator",
          "optional": "true"
        },
        "normalizedLineSeparator": {
          "kind": "attribute",
          "type": "string",
          "description": "The normalized line separator of the files The default value is \n",
          "title": "Normalized Line Separator",
          "optional": "true"
        },
        "comment": {
          "kind": "attribute",
          "type": "string",
          "description": "The comment symbol. The default value is",
          "title": "Comment",
          "optional": "true"
        },
        "lazyLoad": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether the unmarshalling should produce an iterator that reads the lines on the fly or if all the lines must be read at one. The default value is false",
          "title": "Lazy Load",
          "optional": "true"
        },
        "asMap": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether the unmarshalling should produce maps for the lines values instead of lists. It requires to have header (either defined or collected). The default value is false",
          "title": "As Map",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "xmlBeans": {
      "type": "object",
      "title": "Xml Beans",
      "group": "dataformat,transformation",
      "description": "XMLBeans data format",
      "properties": {
        "prettyPrint": {
          "kind": "attribute",
          "type": "bool",
          "description": "To enable pretty printing output nicely formatted. Is by default false.",
          "title": "Pretty Print",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "xmljson": {
      "type": "object",
      "title": "Xmljson",
      "group": "dataformat,transformation",
      "description": "xml-json data format",
      "properties": {
        "encoding": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the encoding. Used for unmarshalling (JSON to XML conversion).",
          "title": "Encoding",
          "optional": "true"
        },
        "elementName": {
          "kind": "attribute",
          "type": "string",
          "description": "Specifies the name of the XML elements representing each array element. Used for unmarshalling (JSON to XML conversion).",
          "title": "Element Name",
          "optional": "true"
        },
        "arrayName": {
          "kind": "attribute",
          "type": "string",
          "description": "Specifies the name of the top-level XML element. Used for unmarshalling (JSON to XML conversion). For example when converting 1 2 3 it will be output by default as 123. By setting this option or rootName you can alter the name of element 'a'.",
          "title": "Array Name",
          "optional": "true"
        },
        "forceTopLevelObject": {
          "kind": "attribute",
          "type": "bool",
          "description": "Determines whether the resulting JSON will start off with a top-most element whose name matches the XML root element. Used for marshalling (XML to JSon conversion). If disabled XML string 12 turns into 'x: '1' 'y': '2' . Otherwise it turns into 'a': 'x: '1' 'y': '2' .",
          "title": "Force Top Level Object",
          "optional": "true"
        },
        "namespaceLenient": {
          "kind": "attribute",
          "type": "bool",
          "description": "Flag to be tolerant to incomplete namespace prefixes. Used for unmarshalling (JSON to XML conversion). In most cases json-lib automatically changes this flag at runtime to match the processing.",
          "title": "Namespace Lenient",
          "optional": "true"
        },
        "rootName": {
          "kind": "attribute",
          "type": "string",
          "description": "Specifies the name of the top-level element. Used for unmarshalling (JSON to XML conversion). If not set json-lib will use arrayName or objectName (default value: 'o' at the current time it is not configurable in this data format). If set to 'root' the JSON string 'x': 'value1' 'y' : 'value2' would turn into value1value2 otherwise the 'root' element would be named 'o'.",
          "title": "Root Name",
          "optional": "true"
        },
        "skipWhitespace": {
          "kind": "attribute",
          "type": "bool",
          "description": "Determines whether white spaces between XML elements will be regarded as text values or disregarded. Used for marshalling (XML to JSon conversion).",
          "title": "Skip Whitespace",
          "optional": "true"
        },
        "trimSpaces": {
          "kind": "attribute",
          "type": "bool",
          "description": "Determines whether leading and trailing white spaces will be omitted from String values. Used for marshalling (XML to JSon conversion).",
          "title": "Trim Spaces",
          "optional": "true"
        },
        "skipNamespaces": {
          "kind": "attribute",
          "type": "bool",
          "description": "Signals whether namespaces should be ignored. By default they will be added to the JSON output using xmlns elements. Used for marshalling (XML to JSon conversion).",
          "title": "Skip Namespaces",
          "optional": "true"
        },
        "removeNamespacePrefixes": {
          "kind": "attribute",
          "type": "bool",
          "description": "Removes the namespace prefixes from XML qualified elements so that the resulting JSON string does not contain them. Used for marshalling (XML to JSon conversion).",
          "title": "Remove Namespace Prefixes",
          "optional": "true"
        },
        "expandableProperties": {
          "kind": "attribute",
          "type": "array",
          "description": "With expandable properties JSON array elements are converted to XML as a sequence of repetitive XML elements with the local name equal to the JSON key for example: number: 123 normally converted to: 123 (where e can be modified by setting elementName) would instead translate to 123 if number is set as an expandable property Used for unmarshalling (JSON to XML conversion).",
          "title": "Expandable Properties",
          "optional": "true"
        },
        "typeHints": {
          "kind": "attribute",
          "type": "string",
          "description": "Adds type hints to the resulting XML to aid conversion back to JSON. Used for unmarshalling (JSON to XML conversion).",
          "title": "Type Hints",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "xmlrpc": {
      "type": "object",
      "title": "Xmlrpc",
      "group": "dataformat,transformation",
      "description": "xml-rpc data format",
      "properties": {
        "request": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to unmarshal request or response Is by default false",
          "title": "Request",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "xstream": {
      "type": "object",
      "title": "Xstream",
      "group": "dataformat,transformation",
      "description": "xstream data format",
      "properties": {
        "encoding": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the encoding to use",
          "title": "Encoding",
          "optional": "true"
        },
        "driver": {
          "kind": "attribute",
          "type": "string",
          "description": "To use a custom XStream driver. The instance must be of type com.thoughtworks.xstream.io.HierarchicalStreamDriver",
          "title": "Driver",
          "optional": "true"
        },
        "driverRef": {
          "kind": "attribute",
          "type": "string",
          "description": "To refer to a custom XStream driver to lookup in the registry. The instance must be of type com.thoughtworks.xstream.io.HierarchicalStreamDriver",
          "title": "Driver Ref",
          "optional": "true"
        },
        "mode": {
          "kind": "attribute",
          "type": "string",
          "description": "Mode for dealing with duplicate references The possible values are: NO_REFERENCES ID_REFERENCES XPATH_RELATIVE_REFERENCES XPATH_ABSOLUTE_REFERENCES SINGLE_NODE_XPATH_RELATIVE_REFERENCES SINGLE_NODE_XPATH_ABSOLUTE_REFERENCES",
          "title": "Mode",
          "optional": "true"
        },
        "converters": {
          "kind": "element",
          "type": "array",
          "description": "List of class names for using custom XStream converters. The classes must be of type com.thoughtworks.xstream.converters.Converter",
          "title": "Converters",
          "optional": "true"
        },
        "aliases": {
          "kind": "element",
          "type": "object",
          "description": "Alias a Class to a shorter name to be used in XML elements.",
          "title": "Aliases",
          "optional": "true"
        },
        "omitFields": {
          "kind": "element",
          "type": "object",
          "description": "Prevents a field from being serialized. To omit a field you must always provide the declaring type and not necessarily the type that is converted.",
          "title": "Omit Fields",
          "optional": "true"
        },
        "implicitCollections": {
          "kind": "element",
          "type": "object",
          "description": "Adds a default implicit collection which is used for any unmapped XML tag.",
          "title": "Implicit Collections",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "zip": {
      "type": "object",
      "title": "Zip",
      "group": "dataformat,transformation",
      "description": "zip data format (not for zip files)",
      "properties": {
        "compressionLevel": {
          "kind": "attribute",
          "type": "number",
          "description": "To specify a specific compression between 0-9. -1 is default compression 0 is no compression and 9 is best compression.",
          "title": "Compression Level",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    },
    "zipFile": {
      "type": "object",
      "title": "Zip File",
      "group": "dataformat,transformation",
      "description": "zip-file data format",
      "properties": {
        "usingIterator": {
          "kind": "attribute",
          "type": "bool",
          "description": "If the zip file has more then one entry the setting this option to true allows to work with the splitter EIP to split the data using an iterator in a streaming mode.",
          "title": "Using Iterator",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the value of the id property.",
          "title": "Id",
          "optional": "true"
        }
      }
    }
  },
  "languages": {
    "constant": {
      "type": "object",
      "title": "Constant",
      "group": "language",
      "description": "For expressions and predicates using a constant",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "el": {
      "type": "object",
      "title": "El",
      "group": "language",
      "description": "For EL expressions and predicates",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "expression": {
      "type": "object",
      "title": "Expression",
      "group": "language",
      "description": "A useful base class for an expression",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "groovy": {
      "type": "object",
      "title": "Groovy",
      "group": "language",
      "description": "For Groovy expressions and predicates",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "header": {
      "type": "object",
      "title": "Header",
      "group": "language",
      "description": "An expression which extracts the named header",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "javaScript": {
      "type": "object",
      "title": "Java Script",
      "group": "language",
      "description": "For JavaScript expressions and predicates",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "jsonpath": {
      "type": "object",
      "title": "Jsonpath",
      "group": "language",
      "description": "For JSonPath expressions and predicates",
      "properties": {
        "resultType": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name of the result type (type from output)",
          "title": "Result Type",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "jxpath": {
      "type": "object",
      "title": "Jxpath",
      "group": "language",
      "description": "For JXPath expressions and predicates",
      "properties": {
        "lenient": {
          "kind": "attribute",
          "type": "bool",
          "description": "Allows to turn lenient on the JXPathContext. When turned on this allows the JXPath expression to evaluate against expressions and message bodies which may be invalid / missing data. This option is by default false",
          "title": "Lenient",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "language": {
      "type": "object",
      "title": "Language",
      "group": "language",
      "description": "Represents a parameterised language expression which can support any language at runtime using the language attribute.",
      "properties": {
        "language": {
          "kind": "attribute",
          "type": "string",
          "description": "The name of the language to use",
          "title": "Language",
          "optional": "false"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "method": {
      "type": "object",
      "title": "Method",
      "group": "language",
      "description": "For expressions and predicates using a java bean (aka method call)",
      "properties": {
        "bean": {
          "kind": "attribute",
          "type": "string",
          "description": "Either a reference or a class name of the bean to use",
          "title": "Bean",
          "optional": "true"
        },
        "ref": {
          "kind": "attribute",
          "type": "string",
          "description": "Reference to bean to lookup in the registry",
          "title": "Ref",
          "optional": "true"
        },
        "method": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of method to call",
          "title": "Method",
          "optional": "true"
        },
        "beanType": {
          "kind": "attribute",
          "type": "string",
          "description": "Class name of the bean to use",
          "title": "Bean Type",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "mvel": {
      "type": "object",
      "title": "Mvel",
      "group": "language",
      "description": "For MVEL expressions and predicates",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "ognl": {
      "type": "object",
      "title": "Ognl",
      "group": "language",
      "description": "For OGNL expressions and predicates",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "php": {
      "type": "object",
      "title": "Php",
      "group": "language",
      "description": "For PHP expressions and predicates",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "property": {
      "type": "object",
      "title": "Property",
      "group": "language",
      "description": "An expression which extracts the named exchange property",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "python": {
      "type": "object",
      "title": "Python",
      "group": "language",
      "description": "For Python expressions and predicates",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "ref": {
      "type": "object",
      "title": "Ref",
      "group": "language",
      "description": "For using a custom expression",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "ruby": {
      "type": "object",
      "title": "Ruby",
      "group": "language",
      "description": "For Ruby expressions and predicates",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "simple": {
      "type": "object",
      "title": "Simple",
      "group": "language",
      "description": "For expressions and predicates using the simple language",
      "properties": {
        "resultType": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name of the result type (type from output)",
          "title": "Result Type",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "spel": {
      "type": "object",
      "title": "Spel",
      "group": "language",
      "description": "For Spring Expression Language (SpEL) expressions and predicates",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "sql": {
      "type": "object",
      "title": "Sql",
      "group": "language",
      "description": "For SQL expressions and predicates",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "terser": {
      "type": "object",
      "title": "Terser",
      "group": "language,hl7",
      "description": "For HL7 terser expressions and predicates",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "tokenize": {
      "type": "object",
      "title": "Tokenize",
      "group": "language",
      "description": "For expressions and predicates using a body or header tokenizer.",
      "properties": {
        "token": {
          "kind": "attribute",
          "type": "string",
          "description": "The (start) token to use as tokenizer for example \n for a new line token",
          "title": "Token",
          "optional": "false"
        },
        "endToken": {
          "kind": "attribute",
          "type": "string",
          "description": "The end token to use as tokenizer if using start/end token pairs.",
          "title": "End Token",
          "optional": "true"
        },
        "inheritNamespaceTagName": {
          "kind": "attribute",
          "type": "string",
          "description": "To inherit namepaces from a root/parent tag name",
          "title": "Inherit Namespace Tag Name",
          "optional": "true"
        },
        "headerName": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of header to tokenize instead of using the message body.",
          "title": "Header Name",
          "optional": "true"
        },
        "regex": {
          "kind": "attribute",
          "type": "bool",
          "description": "If the token is a regular expression pattern. The default value is false",
          "title": "Regex",
          "optional": "true"
        },
        "xml": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether the input is XML messages. This option must be set to true if working with XML payloads.",
          "title": "Xml",
          "optional": "true"
        },
        "includeTokens": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to include the tokens in the parts The default value is false",
          "title": "Include Tokens",
          "optional": "true"
        },
        "group": {
          "kind": "attribute",
          "type": "number",
          "description": "To group N parts together for example to split big files into chunks of 1000 lines.",
          "title": "Group",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "vtdxml": {
      "type": "object",
      "title": "Vtdxml",
      "group": "language",
      "description": "For VTD-XML (fast and efficient XPath) expressions and predicates",
      "properties": {
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "xpath": {
      "type": "object",
      "title": "Xpath",
      "group": "language",
      "description": "For XPath expressions and predicates",
      "properties": {
        "documentType": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of class for document type The default value is org.w3c.dom.Document",
          "title": "Document Type",
          "optional": "true"
        },
        "resultType": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name of the result type (type from output) The default result type is NodeSet",
          "title": "Result Type",
          "optional": "true"
        },
        "saxon": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to use Saxon.",
          "title": "Saxon",
          "optional": "true"
        },
        "factoryRef": {
          "kind": "attribute",
          "type": "string",
          "description": "References to a custom XPathFactory to lookup in the registry",
          "title": "Factory Ref",
          "optional": "true"
        },
        "objectModel": {
          "kind": "attribute",
          "type": "string",
          "description": "The XPath object model to use",
          "title": "Object Model",
          "optional": "true"
        },
        "logNamespaces": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to log namespaces which can assist during trouble shooting",
          "title": "Log Namespaces",
          "optional": "true"
        },
        "headerName": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of header to use as input instead of the message body",
          "title": "Header Name",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "xquery": {
      "type": "object",
      "title": "Xquery",
      "group": "language",
      "description": "For XQuery expressions and predicates",
      "properties": {
        "type": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the class name of the result type (type from output) The default result type is NodeSet",
          "title": "Type",
          "optional": "true"
        },
        "headerName": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of header to use as input instead of the message body",
          "title": "Header Name",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    },
    "xtokenize": {
      "type": "object",
      "title": "Xtokenize",
      "group": "language",
      "description": "For expressions and predicates using a body or header tokenizer.",
      "properties": {
        "headerName": {
          "kind": "attribute",
          "type": "string",
          "description": "Name of header to tokenize instead of using the message body.",
          "title": "Header Name",
          "optional": "true"
        },
        "mode": {
          "kind": "attribute",
          "type": "string",
          "description": "The extraction mode. The available extraction modes are: i - injecting the contextual namespace bindings into the extracted token (default) w - wrapping the extracted token in its ancestor context u - unwrapping the extracted token to its child content t - extracting the text content of the specified element",
          "title": "Mode",
          "optional": "true"
        },
        "group": {
          "kind": "attribute",
          "type": "number",
          "description": "To group N parts together",
          "title": "Group",
          "optional": "true"
        },
        "id": {
          "kind": "attribute",
          "type": "string",
          "description": "Sets the id of this node",
          "title": "Id",
          "optional": "true"
        },
        "expression": {
          "kind": "value",
          "type": "string",
          "description": "The expression value in your chosen language syntax",
          "title": "Expression",
          "optional": "false"
        },
        "trim": {
          "kind": "attribute",
          "type": "bool",
          "description": "Whether to trim the value to remove leading and trailing whitespaces and line breaks",
          "title": "Trim",
          "optional": "true"
        }
      }
    }
  }



};