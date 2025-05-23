import { ErrorRequestHandler } from "express";

const handleErrors: ErrorRequestHandler = (err, req, res, next) => {
    console.log(err);
    res.status(500).send({ message: "Internal Server Error" });
}

export default handleErrors