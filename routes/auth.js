var express = require('express');
var router = express.Router();
let authController = require('../controllers/auth');
let { CreateSuccessResponse, CreateErrorResponse } = require('../utils/responseHandler');
let { check_authentication } = require('../utils/check_auth');
const { SignUpValidator, UpdateAuthValidator, validate } = require('../utils/validator');

/* POST login. */
router.post(
    '/login',
    SignUpValidator, // Sử dụng validator cho đăng nhập
    validate, // Hàm kiểm tra lỗi
    async function (req, res, next) {
        try {
            let { username, password } = req.body;
            let token = await authController.Login(username, password);
            CreateSuccessResponse(res, 200, { token });
        } catch (error) {
            CreateErrorResponse(res, 401, error.message);
        }
    }
);

/* PUT update auth details. */
router.put(
    '/:id',
    check_authentication,
    UpdateAuthValidator, // Sử dụng validator cho cập nhật thông tin auth
    validate, // Hàm kiểm tra lỗi
    async function (req, res, next) {
        try {
            let body = req.body;
            let updatedAuth = await authController.UpdateAuth(req.params.id, body);
            CreateSuccessResponse(res, 200, updatedAuth);
        } catch (error) {
            CreateErrorResponse(res, 400, error.message);
        }
    }
);

router.post('/signup',SignUpValidator,validate, async function (req, res, next) {
        try {
            let newUser = await userController.CreateAnUser(
                req.body.username, req.body.password, req.body.email, 'user'
            )
            CreateSuccessResponse(res, 200, newUser)
        } catch (error) {
            next(error)
        }
    });

router.get('/me', check_authentication, function (req, res, next) {
    CreateSuccessResponse(res, 200, req.user)
})

router.post('/change_password', check_authentication,
    function (req, res, next) {
        try {
            let oldpassword = req.body.oldpassword;
            let newpassword = req.body.newpassword;
            let result = userController.Change_Password(req.user, oldpassword, newpassword)
            CreateSuccessResponse(res, 200, result)
        } catch (error) {
            next(error)
        }
    })

router.post('/forgotpassword', async function (req, res, next) {
    try {
        let email = req.body.email;
        let user = await userController.GetUserByEmail(email);
        user.resetPasswordToken = crypto.randomBytes(32).toString('hex');
        user.resetPasswordTokenExp = (new Date(Date.now() + 10 * 60 * 1000));
        await user.save();
        let url = 'http://localhost:3000/auth/resetpassword/' + user.resetPasswordToken;
        await mailer.sendMailForgotPassword(user.email, url);
        CreateSuccessResponse(res, 200, url)
    } catch (error) {
        next(error)
    }
})
router.post('/resetpassword/:token', async function (req, res, next) {
    try {
        let token = req.params.token;
        let password = req.body.password;
        let user = await userController.GetUserByToken(token);
        user.password = password;
        user.resetPasswordToken = null;
        user.resetPasswordTokenExp = null;
        await user.save();
        CreateSuccessResponse(res, 200, user)
    } catch (error) {
        next(error)
    }
})

module.exports = router;
