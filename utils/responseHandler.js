module.exports = {
    CreateSuccessResponse: function (res, status, data) {
        res.status(status).send({
            success: true,
            data: data
        });
    }, CreateErrorResponse: function (res, status, message) {
        res.status(status).send({
            success: false,
            message: message
        });
    }
}