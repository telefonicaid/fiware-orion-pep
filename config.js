var config = {};

// Protected Resource configuration
//--------------------------------------------------
// Configures the address of the component that is being proxied and the address of the proxy itself.
config.resource = {
    original: {
        /**
         * Host that is being proxied.
         */
        host: 'localhost',

        /**
         * Port where the proxied server is listening.
         */
        port: 10026
    },

    proxy: {
        /**
         * Port where the proxy is listening to redirect requests.
         */
        port: 1026,

        /**
         * Administration port for the proxy.
         */
        adminPort: 11211
    }
};

// Access Control configuration
//--------------------------------------------------
/**
 * This options can be used to configure the address and options of the Access Control, responsible of the request
 * validation.
 */
config.access = {
    /**
     * Indicates whether the access control validation should be disabled. Defaults to false.
     */
    disable: false,

    /**
     * Protocol to use to access the Access Control.
     */
    protocol: 'http',
    /**
     * Host where the Access Control is located.
     */
    host: 'localhost',
    /**
     * Port where the Access Control is listening.
     */
    port: 7070,
    /**
     * Path of the authentication action.
     */
    path: '/pdp/v3',
    /**
     * Enable Log Account user/domain/action.
     */
    account: false,
    /**
     * Log Account file
     */
    accountFile: '/tmp/pepAccount.log',
    /**
     * Account mode: `all`, `matched`, `wrong`
     */
    accountMode: 'all'
};

// User identity configuration
//--------------------------------------------------
/**
 * Information about the Identity Manager server from where the information about a user will be drawn.
 */
config.authentication = {
    checkHeaders: true,
    module: 'keystone',
    user: 'pepproxy',
    password: 'pepproxy',
    domainName: 'admin_domain',
    retries: 3,
    cacheTTLs: {
        users: 1000,
        projectIds: 1000,
        roles: 60,
        validation: 120
    },
    options: {
        protocol: 'http',
        host: 'localhost',
        port: 5000,
        path: '/v3/role_assignments',
        authPath: '/v3/auth/tokens'
    }
};


// Security configuration
//--------------------------------------------------
config.ssl = {
    /**
     * This flag activates the HTTPS protocol in the server. The endpoint always listen to the indicated port
     * independently of the chosen protocol.
     */
    active: false,

    /**
     * Key file to use for codifying the HTTPS requests. Only mandatory when the flag active is true.
     */
    keyFile: '',

    /**
     * SSL Certificate to present to the clients. Only mandatory when the flag active is true.
     */
    certFile: ''
}

/**
 * Default log level. Can be one of: 'DEBUG', 'INFO', 'WARN', 'ERROR', 'FATAL'
 */
config.logLevel = 'FATAL';

// List of component middlewares
//-------------------------------------------------
/**
 * To validate the request, the proxy needs some information that is dependant of the component: the action that a
 * request is going to execute. How to detect the action given the request is component-specific logic, that can be
 * codified in a middleware-like function that will be executed before the user validation. This logic must populate
 * the 'action' parameter of the request.
 */
config.middlewares = {
    /**
     * Indicates the module from where the middlewares will be loaded.
     */
    require: 'lib/plugins/orionPlugin',

    /**
     * Indicates the list of middlewares to load.
     */
    functions: [
        'extractCBAction'
    ]
};

/**
 * If this flag is activated, whenever the pepProxy is not able to redirect a request, instead of returning a 501 error
 * (that is the default functionality) the PEP Proxy process will exit with a -2 code.
 */
config.dieOnRedirectError = false;

/**
 * Name of the component. It will be used in the generation of the FRN.
 */
config.componentName = 'orion';

/**
 * Prefix to use in the FRN (Not to change, usually).
 */
config.resourceNamePrefix = 'fiware:';

/**
 * Indicates whether this PEP should have an admin bypass or not. If it does, whenever a user request arrives to the
 * PEP from a user that has the role defined in the "adminRoleId" property, that request is not validated against the
 * Access Control, but it is automatically proxied instead.
 */
config.bypass = false;

/**
 * ID of the admin user if it exists. Only effective if the "bypass" property is true.
 */
config.bypassRoleId = '';

/**
 * Configures the maximum number of clients that can be simultaneously queued while waiting for the PEP to
 * authenticate itself against Keystone (due to an expired token).
 */
config.maxQueuedClients = 1000;

/**
 * Controls the maximum request body size allowed, in bytes. Default is 1 Mb.
 */
config.bodyLimit = 1048576;

module.exports = config;
