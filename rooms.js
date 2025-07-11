import mongoose from "mongoose";

const connect = mongoose.connect("mongodb://localhost:27017/codecollab")

connect.then(()=>{
    console.log("Database connected");
})
.catch(()=>{
    console.log("Database not connected");
})

const loginschema = new mongoose.Schema({
    roomid:{
        type : Number,
        
    }
})