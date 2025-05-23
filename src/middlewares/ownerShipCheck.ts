const jwt = require('jsonwebtoken');
import User from '../models/AuthModels';
import { Response, NextFunction } from 'express';


export const ownerShipCheck = async (req: any, res: Response, next: NextFunction) => {
    try {
        const token = req.cookies?.utoken;
        if (!token) {
            res.status(401).json({ message: 'No token provided.' });
        } else {
            const decoded = jwt.verify(token, process.env.JWT_SECRET!) as { _id: string };
            const user = await User.findOne({ _id: decoded._id, 'tokens.token': token });

            if (!user) {
                res.status(401).json({ message: 'Invalid token or user not found.' });
            } else {
                req.token = token;
                req.user = user;
            }
        }
        next();
    } catch (err) {
        res.status(401).json({ message: 'Unauthorized. Invalid or expired token.' });
    }
};
