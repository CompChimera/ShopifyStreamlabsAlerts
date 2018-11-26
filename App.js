// Allows us to use proocess.en.VAR_NAME to pull environment variables
const dotenv = require('dotenv').config();

const express = require('express');
const app = express();
const crypto = require('crypto');
const cookie = require('cookie');
const nonce = require('nonce')();
const querystring = require('querystring');
const request = require('request-promise');

// Shopify API Information
const apiKey = process.env.SHOPIFY_API_KEY;
const apiSecret = process.env.SHOPIFY_API_SECRET;
const scopes = 'read_products';
const forwardingAddress = "http://a1048e32.ngrok.io"; // Replace this with your HTTPS Forwarding address

// Homepage
app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(3000, () => {
  console.log('Server started on port 3000');
});

// Shopify install route
app.get('/shopify', (req, res) => {
    // req is the shop id, res is the response
    const shop = req.query.shop;
    if (shop) {
        // nonce is a unique timestamp used for security
        // scope is the type of activity we'll be doing
      const state = nonce();
      const redirectUri = forwardingAddress + '/shopify/callback';
      const installUrl = 'https://' + shop +
        '/admin/oauth/authorize?client_id=' + apiKey +
        '&scope=' + scopes +
        '&state=' + state +
        '&redirect_uri=' + redirectUri;
  
      res.cookie('state', state);
      res.redirect(installUrl);
    } else {
      return res.status(400).send('Missing shop parameter. Please add ?shop=your-development-shop.myshopify.com to your request');
    }
  });

  // Shopify callbackroute
  app.get('/shopify/callback', (req, res) => {
    const { shop, hmac, code, state } = req.query;
    const stateCookie = cookie.parse(req.headers.cookie).state;
  
    if (state !== stateCookie) {
      return res.status(403).send('Request origin cannot be verified');
    }
  
    if (shop && hmac && code) {
        // DONE: Validate request is from Spotify
        const map = Object.assign({}, req.query);
        delete map['signature'];
        delete map['hmac'];
        const message = querystring.stringify(map);
        const providedHmac = Buffer.from(hmac, 'utf-8');
        const generatedHash = Buffer.from(
          crypto
            .createHmac('sha256', apiSecret)
            .update(message)
            .digest('hex'),
            'utf-8'
          );
        let hashEquals = false;
        // timingSafeEqual will prevent any timing attacks. Arguments must be buffers
        try {
          hashEquals = crypto.timingSafeEqual(generatedHash, providedHmac)
        // timingSafeEqual will return an error if the input buffers are not the same length.
        } catch (e) {
          hashEquals = false;
        };
        
        if (!hashEquals) {
          return res.status(400).send('HMAC validation failed');
        }
        
        // DONE: Exchange temporary code for a permanent access token
        const accessTokenRequestUrl = 'https://' + shop + '/admin/oauth/access_token';
        const accessTokenPayload = {
        client_id: apiKey,
        client_secret: apiSecret,
        code,
        };

        request.post(accessTokenRequestUrl, { json: accessTokenPayload })
        .then((accessTokenResponse) => {
            const accessToken = accessTokenResponse.access_token;

            // DONE: Use access token to make API call to 'shop' endpoint
            const shopRequestUrl = 'https://' + shop + '/admin/shop.json';
            const shopRequestHeaders = {
              'X-Shopify-Access-Token': accessToken,
            };
            
            request.get(shopRequestUrl, { headers: shopRequestHeaders })
            .then((shopResponse) => {
              res.end(shopResponse);
            })
            .catch((error) => {
              res.status(error.statusCode).send(error.error.error_description);
            });            
        })
        .catch((error) => {
        res.status(error.statusCode).send(error.error.error_description);
        });
    } else {
      res.status(400).send('Required parameters missing');
    }
  });

