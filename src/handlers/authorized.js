/**
 * Turns the provided handler function into an authorized function.
 * The function passes in the authorized user to the handler.
 * If `forceAuth`, The function throws before calling the handler if the user is not authorized.
 * Otherwise, the user is passed to the handler as null.
 *
 * @param handler A function which takes (req, res, user).
 * @param roles Required roles or empty.
 * @param forceAuth True if the endpoint should throw an error when unauthorized.
 */
module.exports = function(handler, roles=[], forceAuth=true) {
  const getAuthorizedUser = require("./getAuthorizedUser");

  return async (req, res, signal) => {
    const user = await getAuthorizedUser(req, forceAuth);

    if (roles) {
      // Will be thrown if conditions below are not met.
      const e = new Error('Access Denied.');
      e.code = 403;

      if (!user) {
        throw e;
      }

      if (!Array.isArray(roles)) {
        roles = [roles];
      }

      let hasRole = roles.length === 0;
      for (const role of roles) {
        if (user && user.app_metadata && user.app_metadata[role]) {
          hasRole = true;
          break;
        }
      }
      if (!hasRole) {
        throw e;
      }
    }

    return await handler(req, res, user, signal);
  };
};
