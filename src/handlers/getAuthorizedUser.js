/**
 * Ensure the request is authorized and return the authorized user if it is.
 * The user has fields such as: uid, name, email, email_verified, picture.
 *
 * @param req The request
 * @param forceAuth True if the endpoint should throw an error when unauthorized.
 *
 * @return {User} Supabase user or null.
 */
module.exports = async function(req, forceAuth = true) {
  const supabaseClient = global.supabaseClient;

  const TOKEN_PREFIX = "Bearer ";

  const headers = req.headers;

  const handleUnauthorized = () => {
    if (forceAuth) {
      const e = new Error("Access Denied.");
      e.code = 403;
      throw e;
    } else {
      return null;
    }
  };

  if (!headers.authorization || !headers.authorization.startsWith(TOKEN_PREFIX)) {
    return handleUnauthorized();
  }

  const accessToken = headers.authorization.split(TOKEN_PREFIX)[1];

  let user;
  try {
    const response = await supabaseClient.auth.getUser(accessToken);
    if (response.error) {
      handleUnauthorized();
    }
    user = response.data.user;
  } catch (e) {
    return handleUnauthorized();
  }

  return user;
};
