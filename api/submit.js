// Inquiry-form endpoint for My Friendly Care.
// Receives the website inquiry form submission and sends it via the Gmail API
// using a service account with domain-wide delegation.
// Requires GOOGLE_SERVICE_ACCOUNT_KEY set in the Vercel project's Production
// environment variables: the full JSON text of the Google Cloud service account
// key file. No secret is stored in this file.
var crypto = require('crypto');

var IMPERSONATED_USER = 'info@myfriendlycare.com';
var GMAIL_SEND_SCOPE = 'https://www.googleapis.com/auth/gmail.send';
var TOKEN_URL = 'https://oauth2.googleapis.com/token';
var GMAIL_SEND_URL = 'https://gmail.googleapis.com/gmail/v1/users/me/messages/send';

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function signJwt(clientEmail, privateKey) {
  var now = Math.floor(Date.now() / 1000);
  var header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  var claims = base64url(
    JSON.stringify({
      iss: clientEmail,
      sub: IMPERSONATED_USER,
      scope: GMAIL_SEND_SCOPE,
      aud: TOKEN_URL,
      iat: now,
      exp: now + 3600,
    })
  );
  var signingInput = header + '.' + claims;
  var signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  // Tolerate a key pasted with literal "\n" sequences instead of real newlines.
  var key = privateKey.replace(/\\n/g, '\n');
  var signature = signer.sign(key, 'base64');
  var encodedSignature = signature
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return signingInput + '.' + encodedSignature;
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  var body = req.body;
  if (typeof body === 'string') {
    try {
      body = JSON.parse(body);
    } catch (e) {
      return res.status(400).json({ error: 'Invalid request.' });
    }
  }
  if (!body || typeof body !== 'object') {
    return res.status(400).json({ error: 'Invalid request.' });
  }

  var name = typeof body.name === 'string' ? body.name.trim() : '';
  var phone = typeof body.phone === 'string' ? body.phone.trim() : '';
  var email = typeof body.email === 'string' ? body.email.trim() : '';
  var message = typeof body.message === 'string' ? body.message.trim() : '';
  var smsConsent = body.sms_consent === 'Yes' ? 'Yes' : 'No';
  var website = typeof body.website === 'string' ? body.website.trim() : '';

  // Honeypot: if the hidden field was filled, pretend success and send nothing.
  if (website !== '') {
    return res.status(200).json({ ok: true });
  }

  if (!name || !phone || !email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res
      .status(400)
      .json({ error: 'Please fill in your name, phone, and email so we can reach you.' });
  }

  var keyJson = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
  var serviceAccount = null;
  if (keyJson) {
    try {
      serviceAccount = JSON.parse(keyJson);
    } catch (e) {
      serviceAccount = null;
    }
  }
  if (
    !serviceAccount ||
    typeof serviceAccount.client_email !== 'string' ||
    typeof serviceAccount.private_key !== 'string'
  ) {
    console.error('GOOGLE_SERVICE_ACCOUNT_KEY is not configured or invalid.');
    return res.status(502).json({ error: 'Something went wrong. Please try again later.' });
  }

  var assertion;
  try {
    assertion = signJwt(serviceAccount.client_email, serviceAccount.private_key);
  } catch (e) {
    console.error('Failed to sign service account JWT.');
    return res.status(502).json({ error: 'Something went wrong. Please try again later.' });
  }

  var tokenResponse;
  try {
    tokenResponse = await fetch(TOKEN_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body:
        'grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer' +
        '&assertion=' +
        encodeURIComponent(assertion),
    });
  } catch (e) {
    console.error('Token exchange request failed.');
    return res.status(502).json({ error: 'Something went wrong. Please try again later.' });
  }

  if (!tokenResponse.ok) {
    console.error('Token exchange failed with status:', tokenResponse.status);
    return res.status(502).json({ error: 'Something went wrong. Please try again later.' });
  }

  var tokenData;
  try {
    tokenData = await tokenResponse.json();
  } catch (e) {
    tokenData = null;
  }
  if (!tokenData || typeof tokenData.access_token !== 'string') {
    console.error('Token exchange returned no access token.');
    return res.status(502).json({ error: 'Something went wrong. Please try again later.' });
  }

  var subject = 'Website inquiry — My Friendly Care';
  var encodedSubject = '=?UTF-8?B?' + Buffer.from(subject, 'utf8').toString('base64') + '?=';
  var text = [
    'New website inquiry — My Friendly Care',
    '',
    'Name: ' + name,
    'Phone: ' + phone,
    'Email: ' + email,
    'SMS consent: ' + smsConsent,
    '',
    'Message:',
    message || '(no message provided)',
  ].join('\n');

  var mime = [
    'From: My Friendly Care <info@myfriendlycare.com>',
    'To: info@myfriendlycare.com',
    'Cc: jcruz@myfriendlycare.com',
    'Reply-To: ' + email,
    'Subject: ' + encodedSubject,
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset="UTF-8"',
    '',
    text,
  ].join('\r\n');

  var gmailResponse;
  try {
    gmailResponse = await fetch(GMAIL_SEND_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: 'Bearer ' + tokenData.access_token,
      },
      body: JSON.stringify({ raw: base64url(mime) }),
    });
  } catch (e) {
    console.error('Gmail API request failed.');
    return res.status(502).json({ error: 'Something went wrong. Please try again later.' });
  }

  if (!gmailResponse.ok) {
    console.error('Gmail API request failed with status:', gmailResponse.status);
    return res.status(502).json({ error: 'Something went wrong. Please try again later.' });
  }

  return res.status(200).json({ ok: true });
};
