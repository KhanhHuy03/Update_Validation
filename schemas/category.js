let mongoose = require('mongoose');

let categorySchema = mongoose.Schema({
    name:{
        type:String,
        required:true,
        unique:true,
    },description:{
        type:String,
        default:""
    }
},{
    timestamps:true
})
module.exports = mongoose.model('category',categorySchema)
// Tao 1 schema cho obj category gồm name,description, timestamp