import { api, ApiError, IApiRequest } from 'api-gateway-rest-handler';
import * as AWS from 'aws-sdk';

const bucketName = 'yyt-config';

const loadTokens = async (systemKey: string) => {
  const s3 = new AWS.S3();

  const tokensObject = await s3
    .getObject({
      Bucket: bucketName,
      Key: systemKey,
    })
    .promise();
  if (!tokensObject.Body) {
    return [];
  }

  if (!(tokensObject.Body instanceof Buffer)) {
    throw new ApiError('Invalid S3 Body type.', 500);
  }
  const tokens = tokensObject.Body.toString('utf-8');
  return tokens
    .split('\n')
    .map(e => e.trim())
    .filter(Boolean);
};

const ensureSecret = (req: IApiRequest<{}>) => {
  const envSecret = process.env.CONFIG_SECRET;
  if (!envSecret || envSecret !== req.header('X-Auth-Secret')) {
    throw new ApiError('Forbidden', 403);
  }
};

export const authorizeToken = api(async req => {
  ensureSecret(req);

  const { systemKey } = req.pathParameters;
  const normalizedToken = (req.header('X-Auth-Token') || '').trim();
  if (!normalizedToken) {
    throw new ApiError('Invalid token', 400);
  }

  const tokens = await loadTokens(systemKey);
  const s3 = new AWS.S3();
  await s3
    .putObject({
      Bucket: bucketName,
      Key: systemKey,
      Body: Array.from(new Set([...tokens, normalizedToken])).join('\n'),
    })
    .promise();
  return 'ok';
});

export const deleteToken = api(async req => {
  ensureSecret(req);

  const { systemKey } = req.pathParameters;
  const normalizedToken = (req.header('X-Auth-Token') || '').trim();
  if (!normalizedToken) {
    throw new ApiError('Invalid token', 400);
  }

  const tokens = await loadTokens(systemKey);
  const s3 = new AWS.S3();
  await s3
    .putObject({
      Bucket: bucketName,
      Key: systemKey,
      Body: tokens.filter(e => e !== normalizedToken).join('\n'),
    })
    .promise();
  return 'ok';
});

export const listAuthorizedTokens = api(async req => {
  ensureSecret(req);

  const { systemKey } = req.pathParameters;
  const tokens = await loadTokens(systemKey);
  return {
    system: systemKey,
    tokens,
  };
});
