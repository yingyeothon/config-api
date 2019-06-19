import { api, ApiError, IApiRequest } from 'api-gateway-rest-handler';
import * as AWS from 'aws-sdk';

const bucketName = process.env.CONFIG_BUCKET!;
const configSecret = process.env.CONFIG_SECRET!;
const s3 = new AWS.S3();

const loadTokens = async (systemKey: string) => {
  const objectParams = {
    Bucket: bucketName,
    Key: systemKey,
  };
  try {
    const headObject = await s3.headObject(objectParams).promise();
    console.log(headObject);

    const tokensObject = await s3.getObject(objectParams).promise();
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
  } catch (error) {
    if (error.code === 'NotFound') {
      return [];
    }
    console.error(error);
    throw error;
  }
};

const ensureSecret = (req: IApiRequest<{}>) => {
  if (!configSecret || configSecret !== req.header('X-Auth-Secret')) {
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

export const validateToken = api(async req => {
  const { systemKey } = req.pathParameters;
  const normalizedToken = (req.header('X-Auth-Token') || '').trim();
  if (!normalizedToken) {
    return false;
  }
  const tokens = await loadTokens(systemKey);
  return tokens.includes(normalizedToken);
});
