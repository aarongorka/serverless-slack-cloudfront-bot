# CloudFront Bot
CloudFront Bot is a Serverless-powered Slack bot that can invalidate assets in CloudFront distributions.

## Usage
`/cloudfront https://foobar.com.au/asset.png`

## Features
  * You only need to provide a URL, the bot will look up the CloudFront distribution ID for you
  * Can query multiple accounts until it finds the right CloudFront distribution
  * Logging and auditing of all requests made to it

## Deployment

