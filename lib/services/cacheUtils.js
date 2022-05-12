/*
 * Copyright 2014 Telefonica Investigación y Desarrollo, S.A.U
 *
 * This file is part of fiware-pep-steelskin
 *
 * fiware-pep-steelskin is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the License,
 * or (at your option) any later version.
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
 * please contact with::[iot_support@tid.es]
 */

'use strict';

var config = require('../../config'),
    domainModule = require('domain'),
    logger = require('logops'),
    NodeCache = require('node-cache'),
    EventEmitter = require('events').EventEmitter,
    cache;

function createCache() {
    var cacheChannel = new EventEmitter();

    logger.info('Creating caches for services');

    cacheChannel.setMaxListeners(0);

    cache = {
        data: {
            subservice: new NodeCache({
                stdTTL: config.authentication.cacheTTLs.projectIds
            }),
            roles: new NodeCache({
                stdTTL: config.authentication.cacheTTLs.roles
            }),
            user: new NodeCache({
                stdTTL: config.authentication.cacheTTLs.users
            }),
            validation: new NodeCache({
                stdTTL: config.authentication.cacheTTLs.validation
            })
        },
        channel: cacheChannel,
        updating: {
            subservice: {},
            roles: {},
            user: {},
            validation: {}
        }
    };
}

function cleanCache() {
    if (cache && cache.data) {
        cache.data.user = new NodeCache({
            stdTTL: config.authentication.cacheTTLs.users
        });
        cache.data.subservice = new NodeCache({
            stdTTL: config.authentication.cacheTTLs.projectIds
        });
        cache.data.roles = new NodeCache({
            stdTTL: config.authentication.cacheTTLs.roles
        });
        cache.data.validation = new NodeCache({
            stdTTL: config.authentication.cacheTTLs.validation
        });
    }
}

function createDomainEnabledCacheHandler(domain, processValueFn, cache, cacheType, cacheKey, callback) {
    return function(error, value) {
        if (error) {
            logger.debug('Error found creating cache domain handler');
            callback(error);
        } else {
            var currentValue = cache.data[cacheType].get(cacheKey)[cacheKey] || value;
            // Remove domainMiddleware (#498)
            //domain.enter();
            logger.debug('Value found for cache type [%s] key [%s]: %j', cacheType, cacheKey, value);
            logger.debug('Processing with value: %s', JSON.stringify(cache.data[cacheType].get(cacheKey)[cacheKey]));

            processValueFn(currentValue, callback);
        }
    };
}

/**
 * This function introduces a cache in a Keystone function, executing the value processing function with the cached
 * value if there is one that has not expired, or executing the value retrieval function instead. If a request arrives
 * to the cache while the value is being updated, it is put on hold in an event channel, and awaken when the result
 * of the value retrieval has arrived.
 *
 * @param {String} cacheType                Name of the cache (user, roles or subserviceId).
 * @param {String} cacheKey                 Key of the item to retrieve.
 * @param {Function} retrieveRequestFn      Function to call to refresh a particular value.
 * @param {Function} processValueFn         Function to call when the value has been retrieved.
 */
function cacheAndHold(cacheType, cacheKey, retrieveRequestFn, processValueFn, callback) {
    var cachedValue = cache.data[cacheType].get(cacheKey);

    function getCacheEventId() {
        return cacheType + ':' + cacheKey;
    }

    if (cachedValue[cacheKey]) {
        logger.debug('Value found in the cache [%s] for key [%s]: %s', cacheType, cacheKey, cachedValue[cacheKey]);

        processValueFn(cachedValue[cacheKey], callback);
    } else if (cache.updating[cacheType][cacheKey]) {
        logger.debug('Cache type [%s] updating for key [%s]. Waiting.', cacheType, cacheKey);

        cache.channel.on(getCacheEventId(),
            createDomainEnabledCacheHandler(
                domainModule.active,
                processValueFn,
                cache,
                cacheType,
                cacheKey,
                callback)
            );
    } else {
        logger.debug('Value [%s] not found in cache. Retrieving new value.', cacheKey);
        cache.updating[cacheType][cacheKey] = true;
        cache.channel.removeAllListeners(cacheType);
        cache.channel.on(getCacheEventId(), createDomainEnabledCacheHandler(
            domainModule.active,
            processValueFn,
            cache,
            cacheType,
            cacheKey,
            callback
        ));

        retrieveRequestFn(function(error, value) {
            logger.debug('Value [%s] for type [%s] processed with value: %j.', cacheKey, cacheType, value);

            cache.channel.emit(getCacheEventId(), error, value);
            cache.channel.removeAllListeners(getCacheEventId());
        });
    }
}

function get() {
    return cache;
}

exports.clean = cleanCache;
exports.create = createCache;
exports.cacheAndHold = cacheAndHold;
exports.get = get;
