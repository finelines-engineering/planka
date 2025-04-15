const bcrypt = require('bcrypt');
const validator = require('validator');
const ldap = require('ldapjs');
const createUser = require('../users/create');
const { NULL } = require('node-sass');
const { v4: uuid } = require('uuid');

const { getRemoteAddress } = require('../../../utils/remoteAddress');

const Errors = {
  INVALID_CREDENTIALS: {
    invalidCredentials: 'Invalid credentials',
  },
  INVALID_EMAIL_OR_USERNAME: {
    invalidEmailOrUsername: 'Invalid email or username',
  },
  INVALID_PASSWORD: {
    invalidPassword: 'Invalid password',
  },
  INVALID_LDAP: {
    invalidLdap: 'Ldap authentication failed',
  },
  USE_SINGLE_SIGN_ON: {
    useSingleSignOn: 'Use single sign-on',
  },
};

const emailOrUsernameValidator = (value) =>
  value.includes('@')
    ? validator.isEmail(value)
    : value.length >= 3 && value.length <= 16 && /^[a-zA-Z0-9]+((_|\.)?[a-zA-Z0-9])*$/.test(value);

module.exports = {
  inputs: {
    emailOrUsername: {
      type: 'string',
      custom: emailOrUsernameValidator,
      required: true,
    },
    password: {
      type: 'string',
      required: true,
    },
    withHttpOnlyToken: {
      type: 'boolean',
      defaultsTo: false,
    },
  },

  exits: {
    invalidCredentials: {
      responseType: 'unauthorized',
    },
    invalidEmailOrUsername: {
      responseType: 'unauthorized',
    },
    invalidPassword: {
      responseType: 'unauthorized',
    },
    invalidLdap: {
      responseType: 'unauthorized',
    },
    useSingleSignOn: {
      responseType: 'forbidden',
    },
  },



  async fn(inputs) {

    if (sails.config.custom.oidcEnforced) {
      throw Errors.USE_SINGLE_SIGN_ON;
    }

    if(process.env.LDAP_SERVER){
      console.log('AUTH mode : LDAP');

      const server = process.env.LDAP_SERVER;
      const client = ldap.createClient({
          url: `ldap://${server}`
      });

      var token_value = new Promise((resolve) => { client.bind(inputs.emailOrUsername, inputs.password, async (err) => {
        var user;
        var token;
        if(!err){
          console.log('AD connection success');
          user = await sails.helpers.users.getOneByEmailOrUsername(inputs.emailOrUsername);
          if (!user) {
            console.log('Non-existent Planka user: creation in progress');
            await createUser.fn({
              "email": inputs.emailOrUsername,
              "password": inputs.password,
              "isAdmin": false,
              "name": inputs.emailOrUsername,
              "subscribeToOwnCards": false,
              "createdAt": "date",
              "updatedAt": "date"
            });
            user = await sails.helpers.users.getOneByEmailOrUsername(inputs.emailOrUsername);
          }
          token = await sails.helpers.utils.signToken(user.id);
          resolve(token);
        }if(err){
          console.log('AD connection failure');
          token = '';
          resolve(token);
        }
      })});

      // ADMIN CONNEXION
      if (await token_value==''){
        if(inputs.emailOrUsername=='admin' || inputs.emailOrUsername=='admin@admin.admin') {

          console.log('ADMIN CONNEXION');

          var user = await sails.helpers.users.getOneByEmailOrUsername(inputs.emailOrUsername);

          if (!user) {
            throw Errors.INVALID_EMAIL_OR_USERNAME;
          }

          if (!bcrypt.compareSync(inputs.password, user.password)) {
            throw Errors.INVALID_PASSWORD;
          }

          return {
            item: sails.helpers.utils.signToken(user.id),
          };
        }
        throw Errors.INVALID_LDAP;
      }


      return {
        item:  await token_value,
      };



    }

    const remoteAddress = getRemoteAddress(this.req);
    const user = await sails.helpers.users.getOneByEmailOrUsername(inputs.emailOrUsername);

    if (!user) {
      sails.log.warn(
        `Invalid email or username: "${inputs.emailOrUsername}"! (IP: ${remoteAddress})`,
      );

      throw sails.config.custom.showDetailedAuthErrors
        ? Errors.INVALID_EMAIL_OR_USERNAME
        : Errors.INVALID_CREDENTIALS;
    }

    if (user.isSso) {
      throw Errors.USE_SINGLE_SIGN_ON;
    }

    if (!bcrypt.compareSync(inputs.password, user.password)) {
      sails.log.warn(`Invalid password! (IP: ${remoteAddress})`);

      throw sails.config.custom.showDetailedAuthErrors
        ? Errors.INVALID_PASSWORD
        : Errors.INVALID_CREDENTIALS;
    }

    const { token: accessToken, payload: accessTokenPayload } = sails.helpers.utils.createJwtToken(
      user.id,
    );

    const httpOnlyToken = inputs.withHttpOnlyToken ? uuid() : null;

    await Session.create({
      accessToken,
      httpOnlyToken,
      remoteAddress,
      userId: user.id,
      userAgent: this.req.headers['user-agent'],
    });

    if (httpOnlyToken && !this.req.isSocket) {
      sails.helpers.utils.setHttpOnlyTokenCookie(httpOnlyToken, accessTokenPayload, this.res);
    }

    return {
      item: accessToken,
    };
  },
};
