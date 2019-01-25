'use strict'

/*
 * adonis-ally
 *
 * (c) Joshua Tanner @tanner_geo
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
*/

const got = require('got')

const CE = require('../Exceptions')
const OAuth2Scheme = require('../Schemes/OAuth2')
const AllyUser = require('@adonisjs/ally/src/AllyUser')
const utils = require('../../lib/utils')
const _ = require('lodash')

/**
 * ArcGIS driver to authenticate users via OAuth2
 * scheme.
 *
 * @class ArcGIS
 * @constructor
 */
class ArcGIS extends OAuth2Scheme {
  constructor (Config) {
    const config = Config.get('services.ally.arcgis')

    utils.validateDriverConfig('arcgis', config)
    utils.debug('arcgis', config)

    super(config.clientId, config.clientSecret, config.headers)
  }

  /**
   * Injections to be made by the IoC container
   *
   * @attribute inject
   *
   * @return {Array}
   */
  static get inject () {
    return ['Adonis/Src/Config']
  }

  /**
   * Returns a boolean telling if driver supports
   * state
   *
   * @method supportStates
   *
   * @return {Boolean}
   */
  get supportStates () {
    return false
  }

  /**
   * Scope seperator for seperating multiple
   * scopes.
   *
   * @attribute scopeSeperator
   *
   * @return {String}
   */
  get scopeSeperator () {
    return ' '
  }

  /**
   * Base url to be used for constructing
   * facebook oauth urls.
   *
   * @attribute baseUrl
   *
   * @return {String}
   */
  get baseUrl () {
    return 'https://www.arcgis.com/sharing/rest/oauth2'
  }

  /**
   * Relative url to be used for redirecting
   * user.
   *
   * @attribute authorizeUrl
   *
   * @return {String} [description]
   */
  get authorizeUrl () {
    return 'authorize'
  }

  /**
   * Relative url to be used for exchanging
   * access token.
   *
   * @attribute accessTokenUrl
   *
   * @return {String}
   */
  get accessTokenUrl () {
    return 'token'
  }

  /**
   * Returns the user profile as an object using the
   * access token.
   *
   * @method _getUserProfile
   * @async
   *
   * @param   {String} accessToken
   *
   * @return  {Object}
   *
   * @private
   */
  async _getUserProfile (accessToken) {
    const profileUrl = `https://www.arcgis.com/sharing/rest/community/self?token=${accessToken}&f=json`

    const response = await got(profileUrl, {
      headers: {
        'Accept': 'application/json',
      },
      json: true
    })

    return response.body
  }

  /**
   * Normalize the user profile response and build an Ally user.
   *
   * @param {object} userProfile
   * @param {object} accessTokenResponse
   *
   * @return {object}
   *
   * @private
   */
  _buildAllyUser (userProfile, accessTokenResponse) {
    const user = new AllyUser()
    const expires = _.get(accessTokenResponse, 'result.expires')

    user.setOriginal(userProfile)
      .setFields(
        userProfile.username,
        userProfile.fullName,
        userProfile.email,
        userProfile.username,
        userProfile.thumbnail
      )
      .setToken(
        accessTokenResponse.token,
        null,
        null,
        expires ? Number(expires) : null
      )

    return user
  }

  /**
   * Returns the redirect url for a given provider
   *
   * @method getRedirectUrl
   *
   * @param {String} [state]
   *
   * @return {String}
   */
  async getRedirectUrl (state) {
    const options = state ? Object.assign(this._redirectUriOptions, { state }) : this._redirectUriOptions
    return this.getUrl(this._redirectUri, this.scope, options)
  }

  /**
   * Parser error mentioned inside the result property
   * of the oauth response.
   *
   * @method parseProviderResultError
   *
   * @param  {Object} response
   *
   * @throws {OAuthException} If response has error property
   */
  parseProviderResultError (response) {
    const message = response.error_description || response.error
    return CE.OAuthException.tokenExchangeException(message, null, response)
  }

  /**
   * Parses the redirect errors returned by arcgis
   * and returns the error message.
   *
   * @method parseRedirectError
   *
   * @param  {Object} queryParams
   *
   * @return {String}
   */
  parseRedirectError (queryParams) {
    return queryParams.error_description
      ? `${queryParams.error_description}. Learn more: ${queryParams.error_uri}`
      : 'Oauth failed during redirect'
  }

  /**
   * Returns the user profile with it's access token, refresh token
   * and token expiry.
   *
   * @method getUser
   * @async
   *
   * @param {Object} queryParams
   * @param {String} [originalState]
   *
   * @return {Object}
   */
  async getUser (queryParams, originalState) {
    const code = queryParams.code
    const state = queryParams.state

    /**
     * Throw an exception when query string does not have
     * code.
     */
    if (!code) {
      const errorMessage = this.parseRedirectError(queryParams)
      throw CE.OAuthException.tokenExchangeException(errorMessage, null, errorMessage)
    }

    /**
     * Valid state with original state
     */
    if (state && originalState !== state) {
      throw CE.OAuthException.invalidState()
    }

    const accessTokenResponse = await this.getAccessToken(code, this._redirectUri, {
      grant_type: 'authorization_code'
    })

    const userProfile = await this._getUserProfile(accessTokenResponse.accessToken)
    return this._buildAllyUser(userProfile, accessTokenResponse)
  }

  /**
   *
   * @param {string} accessToken
   */
  async getUserByToken (accessToken) {
    const userProfile = await this._getUserProfile(accessToken)

    return this._buildAllyUser(userProfile, { accessToken, refreshToken: null })
  }
}

module.exports = ArcGIS
