"use strict";
// -- Authentification Control System
//
// Castellon.CH - 2019 (c)
// Author: Antonio Castellon - antonio@castellon.ch
//
// to be used in front of all u-services that are used directly from the browser client
//
const os 	= require("os");
const ntlm  = require('express-ntlm');
const jwt   = require('jsonwebtoken');  // https://www.npmjs.com/package/jsonwebtoken
const secureRandom = require("secure-random");

module.exports = function(setup) {

  const PASS_TOKEN = setup.passToken || secureRandom(256, { type: "Buffer" });
  const model = {};

  let ldapCache = new Array();

  //
  // CONFIGURATION
  //
  const ldap = require('@acastellon/ldap')(setup);
  //const ldap = require('../../modules/ldap/ldap.js')(setup);

  //
  // ASSIGNATIONS
  //

  model.setNTLMAuth = setNTLMAuth;
  model.validateToken = validateToken;
  model.setRoles = setRoles;
  model.getRoles = getRoles;
  model.removeCache4 = removeCache4;

  //
  //  FUNCTION BODY
  //

  function getHostName(){
    return process.env.CNAME || os.hostname();
  }

  function removeCache4(userName){
    ldapCache[userName] = null;
  }


  function setContent(into, from){

    Object.keys(from).forEach(function(value){
      if (value.startsWith('is')){
        into[value] = from[value];
      }
    });

  }

  function setHeaders(res, v){

    Object.keys(v).forEach(function(value) {
      if (value.startsWith('is')){
        res.setHeader(value, v[value]);
      }
    });

  }


  /**
   * Include the Authentication NTLM control inside of the usage from EXPRESS
   * @param app - the express application to  include the control
   */
  function setNTLMAuth (app) {

    app.use(ntlm({
      debug: function () {
        if (setup.NTLM_DEBUG) {
          var args = Array.prototype.slice.apply( arguments );
          console.log.apply( null, args );
        }
      },
      domain: ldap.DOMAIN,
      domaincontroller: ldap.LDAP_URL,
      forbidden: function (req, res) {
        res
          .status(401)
          .location(req.url).end();
      }
    }));

    app.all('*', function (request, res, next) {

      let userName = request.ntlm.UserName;

      if(ldapCache[userName] != null){

        if (jwt.decode(ldapCache[userName]).exp >= new Date().getTime()/1000) {
          res.setHeader("x-access-token", ldapCache[userName]);
          res.setHeader("is-authenticated", true);
          res.setHeader("auth-user", userName);

          next();
          return;
        }

      }

      //
      // in this other case, look for the validation in LDAP
      //

      if (request.ntlm.Authenticated
          && !res.hasHeader('is-authenticated'))
      {

        res.setHeader("is-authenticated", true);
        res.setHeader("auth-user", userName);

        let _content = {
          id: userName
        }

        ldap.getRoles(userName).then(function (v) {

          setContent(_content, v);

         // console.log(_content);

          // create a token
          let token = jwt.sign(_content, PASS_TOKEN, {
            expiresIn: setup.EXPIRES
          });

          res.setHeader("x-access-token", token);

          // console.log(' ..... INCLUDING CACHE for ' + userName);

          ldapCache[userName] =  token;

          next();
        })


      } else {

        Object.keys(setup.ROLES)
              .forEach(function(value){
                  res.setHeader(value, false);
        });

        res.setHeader("x-access-token", null);

        ldapCache[userName] = null;

        res.status(401).json({Message: 'Unauthorized access ', AuthUser: userName});
      }
    });
  }

  function isEqualToken (token, _token, userName) {

    let allRoles = true;
    Object.keys(setup.ROLES)
        .forEach(function(value) {
          allRoles = allRoles && (jwt.decode( token )[value] == jwt.decode( _token )[value]);
        });

    return allRoles
            && (jwt.decode(token).id == jwt.decode(_token).id)
            && (jwt.decode(token).id == userName)
            ;
  }

  /**
   * Validate the JWToken and get the correct roles associated to the user using LDAP
   * @param app
   */
  function validateToken (app) {

    app.all('*', function (req, res, next) {

      let token = req.headers['x-access-token'];
      let userName = req.headers['auth-user'];

      if (userName == 'service-brother'
        && req.get('host').startsWith(getHostName()))
      {
        next();
      }
      else{

            let _content = {id: userName};

            ldap.getRoles(userName).then(function (v) {

              setContent(_content, v);
              setHeaders(res,v);
              res.setHeader("auth-user", userName);

              var _token = jwt.sign(_content, PASS_TOKEN , {
                expiresIn: setup.EXPIRES
              });

              if (!token || !isEqualToken(token, _token, userName)) return res.status(403).send({
                auth: false,
                message: 'No token provided, or incorrect ones.',
                host : getHostName(),
                origin: req.get('host'),
                user : userName
              });

              jwt.verify(token, PASS_TOKEN , function (err, decoded) {
                if (err)
                {
                  return res.status(500).send({auth: false, message: 'Failed to authenticate token. Maybe token is expired.'});
                }
                else{
                  next();
                }
              });

            })
      }
   });
  }

  function setRoles (app) {
    app.all('*', function (req, res, next) {

      let userName = req.headers['auth-user'];

      if (typeof userName == 'undefined' || userName == '') {
        res.status(401).send({message: 'Authentication required'});
      } else {
        ldap.getRoles(userName).then(function (v) {
          setHeaders(res, v);
          res.setHeader("auth-user", userName);
          next();
        });
      }

    });
  }


  function getRoles(req, res)
  {
    let userName = '';

    if (typeof req.ntlm != 'undefined')
    {
      userName = req.ntlm.UserName || req.headers['auth-user'] ;
    }
    else {
      userName = req.headers['auth-user'] ;
    }

    if (typeof userName == 'undefined' || userName == '') {
      res.status(401).send({message: 'Authentication required'});
    } else {
      ldap.getRoles(userName).then(function (v) {
        res.json(v);
      });
    }
  }

  return model;
}
