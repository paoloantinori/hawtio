/**
 * @module RHAccess
 */
var RHAccess = (function (RHAccess) {

    RHAccess.rhAccessContextPath = "/rhaccess-web/";

    RHAccess.remoteAppEntryPoint = RHAccess.rhAccessContextPath + "support.html";

    RHAccess.localAppEntryPoint = "index.html#/rhaccess_plugin";

    /**
   * @property breadcrumbs
   * @type {{content: string, title: string, isValid: isValid, href: string}[]}
   *
   * Data structure that defines the sub-level tabs for
   * our plugin, used by the navbar controller to show
   * or hide tabs based on some criteria
   */
    /**
     * @property breadcrumbs
     * @type {{content: string, title: string, isValid: isValid, href: string}[]}
     *
     * Data structure that defines the sub-level tabs for
     * our plugin, used by the navbar controller to show
     * or hide tabs based on some criteria
     */
    RHAccess.breadcrumbs = [
        //_href is the value used by the ng-click directive to alter the iframe destination

        {
            content: '<i class="icon-warning-sign"></i> Open New Case',
            title: "Open a new Case",
            isValid: function () { return true; },
            href: RHAccess.localAppEntryPoint,
            _href: RHAccess.remoteAppEntryPoint + "#case/new",
            isActive: false
        },
        {
            content: '<i class="icon-th-list"></i> List Cases',
            title: "List Cases",
            isValid: function () { return true; },
            href: RHAccess.localAppEntryPoint,
            _href: RHAccess.remoteAppEntryPoint + "#case/list"
        },
        {
            content: '<i class="icon-stethoscope"></i> Diagnose Log',
            title: "Diagnose Log",
            isValid: function () { return true; },
            href: RHAccess.localAppEntryPoint,
            _href: RHAccess.remoteAppEntryPoint + "#logviewer",
            isActive: false
        },
        {
            content: '<i class="icon-book"></i> Search Knowledge Base',
            title: "Search Knowledge Base",
            isValid: function () { return true },
            href: RHAccess.localAppEntryPoint,
            _href: RHAccess.remoteAppEntryPoint + "#search",
            isActive: true
        }
    ];

    /**
     * @function NavBarController
     *
     * @param $scope
     * @param workspace
     *
     * The controller for this plugin's navigation bar
     *
     */
    RHAccess.NavBarController = function($scope, RHAccessSharedProperties) {

        $scope.sharedProperties = RHAccessSharedProperties;
        $scope.breadcrumbs = RHAccess.breadcrumbs;

        $scope.isValid = function(link) {
            return link.isValid();
        };
    
        $scope.updateIframe = function(link) {
            $scope.sharedProperties.iframeUrl = link._href;
            link.isActive = true;
          
            $scope.breadcrumbs.forEach(function(element){
              
              if(element != link){
                element.isActive = false;
              }
            });

            true;
        }

    };

  return RHAccess;

} (RHAccess || {}));
