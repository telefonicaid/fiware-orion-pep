/*
 * Copyright 2014 Telefonica Investigación y Desarrollo, S.A.U
 *
 * This file is part of fiware-pep-steelskin

 * fiware-pep-steelskin is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version
 *
 * fiware-pep-steelskin is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public
 * License along with fiware-pep-steelskin.
 * If not, seehttp://www.gnu.org/licenses/.
 *
 * For those usages not covered by the GNU Affero General Public License
 * please contact with::[daniel.moranjimenez@telefonica.com]
 */

'use strict';

var express = require('express'),
    utils = require('./utils'),
    http = require('http');

/**
 * Middleware that makes Express read the incoming body if the content-type is text/xml or application/xml (the default
 * behavior is to read the body if it can be parsed and leave it unread in any other case).
 *
 * @param {Object} req           Incoming request.
 * @param {Object} res           Outgoing response.
 * @param {Function} next        Invokes the next middleware in the chain.
 */
function xmlRawBody(req, res, next) {
    var contentType = req.headers['content-type'] || '',
        mime = contentType.split(';')[0];

    if (mime !== 'text/xml' && mime !== 'application/xml') {
        next();
    } else {
        var data = '';
        req.setEncoding('utf8');
        req.on('data', function(chunk) {
            data += chunk;
        });
        req.on('end', function() {
            req.rawBody = data;
            next();
        });
    }
}

function startMock(port, callback) {
    var app = express();

    app.set('port', port);
    app.set('host', 'localhost');
    app.use(express.json());
    app.use(xmlRawBody);
    app.use(express.urlencoded({ extended: true }));

    var server = http.createServer(app);

    server.listen(app.get('port'), app.get('host'), function(error) {
        callback(error, server, app);
    });
}

function stopMock(server, callback) {
    server.close(callback);
}

function mockPath(url, app, callback) {
    function mock(req, res) {
        if (app.handler) {
            app.handler(req, res);
        } else {
            res.status(200).json({});
        }
    }

    app.delete(url, mock);
    app.get(url, mock);
    app.post(url, mock);
    app.put(url, mock);
    callback();
}

function mockKeystone(req, res) {
    if (req.path === '/v3/auth/tokens' && req.method === 'POST') {
        res.setHeader('X-Subject-Token', '092016b75474ea6b492e29fb69d23029');
        res.status(201).json(utils.readExampleFile('./test/keystoneResponses/authorize.json'));
    } else if (req.path === '/v3/auth/tokens' && req.method === 'GET') {
        res.status(200).json(utils.readExampleFile('./test/keystoneResponses/getUser.json'));
    } else if (req.path === '/v3/projects' && req.method === 'GET') {
        res.status(200).json(utils.readExampleFile('./test/keystoneResponses/getProjects.json'));
    } else {
        res.status(200).json(utils.readExampleFile('./test/keystoneResponses/rolesOfUser.json'));
    }
}

exports.start = startMock;
exports.stop = stopMock;
exports.mockPath = mockPath;
exports.mockKeystone = mockKeystone;
