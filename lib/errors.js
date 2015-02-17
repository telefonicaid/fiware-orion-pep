/*
 * Copyright 2014 Telefonica Investigación y Desarrollo, S.A.U
 *
 * This file is part of fiware-orion-pep
 *
 * fiware-orion-pep is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
 *
 * fiware-orion-pep is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with fiware-orion-pep.
 * If not, seehttp://www.gnu.org/licenses/.
 *
 * For those usages not covered by the GNU Affero General Public License
 * please contact with::[iot_support@tid.es]
 */

var util = require('util');

var errors = {
    OrganizationNotFound: function() {
        this.name = 'ORGANIZATION_NOT_FOUND';
        this.message = 'Organization not found';
    },
    UserNotFound: function() {
        this.name = 'USER_NOT_FOUND';
        this.message = 'User credentials not found';
    },
    TokenDoesNotMatchService: function() {
        this.name = 'TOKEN_DOES_NOT_MATCH_SERVICE';
        this.message = 'The provided token does not belong to the provided service.';
    },
    ActionNotFound: function() {
        this.name = 'ACTION_NOT_FOUND';
        this.message = 'The system wasn\'t able to guess the action type or the request';
    },
    WrongXmlPayload: function() {
        this.name = 'WRONG_XML_PAYLOAD';
        this.message = 'The system wasn\'t able to parse the given XML payload';
    },
    WrongJsonPayload: function() {
        this.name = 'WRONG_JSON_PAYLOAD';
        this.message = 'The system wasn\'t able to parse the given JSON payload (either it was empty or wrong)';
    },
    WrongXmlValidationResponse: function() {
        this.name = 'WRONG_XML_VALIDATION_RESPONSE';
        this.message = 'The system wasn\'t able to parse the XML obtained from the Access Control';
    },
    KeystoneConnectionError: function(e) {
        this.name = 'KEYSTONE_CONNECTION_ERROR';
        this.message = 'There was a connection error accessing the Access Control: ' + e.message;
    },
    KeystoneValidationError: function(message) {
        this.name = 'KEYSTONE_VALIDATION_ERROR';
        this.message = 'The Access Control failed to make a decision due to the following error: ' + message;
    },
    KeystoneAuthenticationError: function(msg) {
        this.name = 'KEYSTONE_AUTHENTICATION_ERROR';
        this.message = 'There was a connection error while authenticating to Keystone: ' + msg;
    },
    KeystoneAuthenticationRejected: function(code) {
        this.name = 'KEYSTONE_AUTHENTICATION_REJECTED';
        this.message = 'User authentication was rejected with code: ' + code;
    },
    KeystoneSubserviceNotFound: function(name) {
        this.name = 'KEYSTONE_SUBSERVICE_NOT_FOUND';
        this.message = 'Could not find subservice with name [' + name + '] in Keystone.';
    },
    PepProxyAuthenticationRejected: function(code) {
        this.name = 'PEP_PROXY_AUTHENTICATION_REJECTED';
        this.message = 'Proxy authentication was rejected with code: ' + code;
    },
    RolesNotFound: function(subservice) {
        this.name = 'ROLES_NOT_FOUND';
        this.message = 'No roles were found for the user token in the give subservice: ' + subservice;
    },
    AccessDenied: function() {
        this.name = 'ACCESS_DENIED';
        this.message = 'The user does not have the appropriate permissions to access the selected action';
    },
    TemplateLoadingError: function(e) {
        this.name = 'TEMPLATE_LOADING_ERROR';
        this.message = 'There was an error loading the templates for the validation Request: ' + e.message;
    },
    UnexpectedContentType: function(contentType) {
        this.name = 'UNEXPECTED_CONTENT_TYPE';
        this.message = 'The MIME content type received is not supported: ' + contentType;
    },
    TargetServerError: function(msg) {
        this.name = 'TARGET_SERVER_ERROR';
        this.message = 'There was an error redirecting the request to the target server: ' + msg;
    }
};

for (var errorFn in errors) {
    if (errors.hasOwnProperty(errorFn)) {
        util.inherits(errors[errorFn], Error);
    }
}

module.exports = errors;
