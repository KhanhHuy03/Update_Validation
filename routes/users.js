var express = require('express');
var router = express.Router();
let userController = require('../controllers/users');
let { CreateSuccessResponse, CreateErrorResponse } = require('../utils/responseHandler');
let { check_authentication, check_authorization } = require('../utils/check_auth');
const constants = require('../utils/constants');
const { SignUpValidator, validate } = require('../utils/validator');

/* GET users listing. */
router.get('/', check_authentication, check_authorization(constants.MOD_PERMISSION), async function (req, res, next) {
  console.log(req.headers.authorization);
  let users = await userController.GetAllUser();
  CreateSuccessResponse(res, 200, users);
});

router.post(
  '/',
  check_authentication,
  check_authorization(constants.ADMIN_PERMISSION),
  SignUpValidator, 
  validate, 
  async function (req, res, next) {
    try {
      let body = req.body;
      let newUser = await userController.CreateAnUser(body.username, body.password, body.email, body.role);
      CreateSuccessResponse(res, 200, newUser);
    } catch (error) {
      CreateErrorResponse(res, 404, error.message);
    }
  }
);

router.put(
  '/:id',
  check_authentication,
  check_authorization(constants.ADMIN_PERMISSION),
  [
    body('username').optional().isLength({ min: 6 }).withMessage('Username must be at least 6 characters long'),
    body('password')
      .optional()
      .isStrongPassword({
        minLength: 8,
        minLowercase: 1,
        minUppercase: 1,
        minNumbers: 1,
        minSymbols: 1,
      })
      .withMessage('Password must meet strength requirements'),
    body('email').optional().isEmail().withMessage('Invalid email format'),
    body('role').optional().isString().withMessage('Role must be a string'),
  ],
  validate, 
  async function (req, res, next) {
    try {
      let body = req.body;
      let updatedResult = await userController.UpdateAnUser(req.params.id, body);
      CreateSuccessResponse(res, 200, updatedResult);
    } catch (error) {
      next(error);
    }
  }
);

module.exports = router;
