/*!
 * Copyright 2014 Red Hat, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
'use strict'
const URL = require('url')
const http = require('http')
const https = require('https')
const jwkToPem = require('jwk-to-pem')
const HttpProxyAgent = require('http-proxy-agent');
const HttpsProxyAgent = require('https-proxy-agent');

/**
 * Construct a Rotation instance
 *
 * @param {Config} config Config object.
 *
 * @constructor
 */
function Rotation (config) {
  this.realmUrl = config.realmUrl
  this.minTimeBetweenJwksRequests = config.minTimeBetweenJwksRequests
  this.jwks = []
  this.lastTimeRequesTime = 0
  this.useProxy = config.useProxy
  console.log('config', JSON.stringify(config))
}

Rotation.prototype.retrieveJWKs = function retrieveJWKs (callback) {
  const url = this.realmUrl + '/protocol/openid-connect/certs'
  const options = URL.parse(url); // eslint-disable-line
  options.method = 'GET'

  const promise = new Promise((resolve, reject) => {
    const req = getProtocol(options).request(withProxy(options), (response) => {
      if (response.statusCode < 200 || response.statusCode >= 300) {
        return reject(new Error('Error fetching JWK Keys'))
      }
      let json = ''
      response.on('data', (d) => (json += d.toString()))
      response.on('end', () => {
        const data = JSON.parse(json)
        if (data.error) reject(data)
        else resolve(data)
      })
    })
    req.on('error', reject)
    req.end()
  })
  return nodeify(promise, callback)
}

Rotation.prototype.getJWK = function getJWK (kid) {
  const key = this.jwks.find((key) => { return key.kid === kid })
  if (key) {
    return new Promise((resolve, reject) => {
      resolve(jwkToPem(key))
    })
  }
  const self = this

  // check if we are allowed to send request
  const currentTime = new Date().getTime() / 1000
  if (currentTime > this.lastTimeRequesTime + this.minTimeBetweenJwksRequests) {
    return this.retrieveJWKs()
      .then(publicKeys => {
        self.lastTimeRequesTime = currentTime
        self.jwks = publicKeys.keys
        const convertedKey = jwkToPem(self.jwks.find((key) => { return key.kid === kid }))
        return convertedKey
      })
  } else {
    console.error('Not enough time elapsed since the last request, blocking the request')
  }
}

Rotation.prototype.clearCache = function clearCache () {
  this.jwks.length = 0
}

const getProtocol = (opts) => {
  return opts.protocol === 'https:' ? https : http
}

const withProxy = (opts) => {
  console.log('run with proxy...', this.useProxy)
  if (this.useProxy === true) {
    opts.agent = opts.protocol === 'https:' ?
        new HttpsProxyAgent(process.env.HTTPS_PROXY | process.env.https_proxy) :
        new HttpProxyAgent(process.env.HTTP_PROXY | process.env.http_proxy)
  }

  console.log('use https', opts.protocol === 'https:')
  console.log(process.env.HTTPS_PROXY | process.env.https_proxy)
  console.log(process.env.HTTP_PROXY | process.env.http_proxy)

  return opts
}

const nodeify = (promise, cb) => {
  if (typeof cb !== 'function') return promise
  return promise.then((res) => cb(null, res)).catch((err) => cb(err))
}

module.exports = Rotation
