'use strict';

// Setting up route
angular.module('core.admin').config(['$stateProvider',
  function ($stateProvider) {
    $stateProvider
      .state('admin', {
        abstract: true,
        url: '/admin',
        template: '<ui-view/>',
        data: { roles: ['admin'] }
      });
  }
]);
