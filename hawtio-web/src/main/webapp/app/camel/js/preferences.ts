/**
 * @module Camel
 */
/// <reference path="camelPlugin.ts"/>
module Camel {
  _module.controller("Camel.PreferencesController", ["$scope", "localStorage", ($scope, localStorage) => {
    Core.initPreferenceScope($scope, localStorage, {
      'camelIgnoreIdForLabel': {
        'value': false,
        'converter': Core.parseBooleanValue
      },
      'camelMaximumLabelWidth': {
        'value': Camel.defaultMaximumLabelWidth,
        'converter': parseInt
      },
      'camelMaximumTraceOrDebugBodyLength': {
        'value': Camel.defaultCamelMaximumTraceOrDebugBodyLength,
        'converter': parseInt
      },
      'camelRouteMetricMaxSeconds': {
        'value': Camel.defaultCamelRouteMetricMaxSeconds,
        'converter': parseInt
      },
      'camelShowEIPDocumentation': {
        'value': Camel.defaultShowEIPDocumentation,
        'converter': Core.parseBooleanValue
      },
      'camelHideUnusedEIP': {
        'value': Camel.defaultHideUnusedEIP,
        'converter': Core.parseBooleanValue
      }
    });
  }]);
}
