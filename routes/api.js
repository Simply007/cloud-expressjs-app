const express = require('express');
const router = express.Router();
const crypto = require('crypto');

const isValidSignature = (req, secret) => {
  const givenSignature = req.headers['x-kc-signature'];
  const computedSignature = crypto.createHmac('sha256', secret)
      .update(req.rawBody)
      .digest();

  return crypto.timingSafeEqual(Buffer.from(givenSignature, 'base64'), computedSignature);
}

router.get('/api/kchook', (req, res, next) => {
  //eslint-disable-next-line no-process-env
  if (!isValidSignature(req, process.env['KC_WEBHOOK_SECRET'])) {
    //eslint-disable-next-line no-console
    console.error('Signature was invalid');

    return;
  }

  // Do what you want with the hook
  //eslint-disable-next-line no-console
  console.log(JSON.stringify(req, null, 2));

});

module.exports = router;