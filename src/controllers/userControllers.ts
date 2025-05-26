import { Request, Response, NextFunction } from 'express';
import User, { IToken } from '../models/AuthModels';
import { AuthenticatedRequest } from '../middlewares/auth';
import PasswordResetToken from '../models/PasswrodResetModel';
import { config } from '../config/test-config';

const jwt = require("jsonwebtoken")
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer')

const registerForm = (req: Request, res: Response): void => {
    res.render('register');
};

const loginForm = (req: Request, res: Response): void => {
    res.render('login');
};

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER!,
        pass: process.env.EMAIL_PASS!
    }
});

const registerNewUser = async (req: Request, res: Response): Promise<void> => {
    try {
        const { user_name, email, password } = req.body;

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            res.status(409).json({ message: 'Email already exists.' });
            return;
        }

        const registerUser = new User({ user_name, email, password });
        await registerUser.save();

        res.status(201).json({
            message: 'Registration successful.',
        });

    } catch (err) {
        res.status(500).json({
            message: 'Server error. Please try again later.',
        });
    }
};

const login = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            res.status(401).json({ message: "Invalid Credentials." });
            return;
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            res.status(401).json({ message: 'Invalid Credentials.' });
            return;
        }

        const { accessToken, refreshToken } = await user.generateAuthToken();


        res.cookie("accessToken", accessToken, {
            expires: new Date(Date.now() + 15 * 60 * 1000), //15m
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });

        res.cookie("refreshToken", refreshToken, {
            expires: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict',
            path: '/api/auth/refresh'
        });

    } catch (e) {
        console.error('Login error:', e);
        res.status(500).json({
            message: 'Something went wrong.',
        });
    }
}

const refreshToken = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
        const refreshToken = req.cookies.refreshToken || req.body.refreshToken;

        if (!refreshToken) {
            res.status(401).json({ message: 'No refresh token provided' });
            return;
        }

        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET!) as { _id: string };
        const user = await User.findOne({
            _id: decoded._id,
            'tokens.token': refreshToken,
            'tokens.type': 'refresh'
        });

        if (!user) {
            res.status(401).json({ message: 'Invalid refresh token' });
            return;
        }

        const accessToken = user.generateAuthToken();

        // Removing old accesstokens
        user.tokens = user.tokens.filter((token: IToken) => token.type !== 'access');
        user.tokens.push({
            token: accessToken,
            type: 'access',
            expiresAt: new Date(Date.now() + 15 * 60 * 1000) // 15 m
        } as IToken);  // Explicitly type the object being pushed

        await user.save();

        // Set newaccesstoken 
        res.cookie("accessToken", accessToken, {
            expires: new Date(Date.now() + 15 * 60 * 1000), // 15 m
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'strict'
        });

        res.status(200).json({
            message: 'Token refreshed successfully',
            accessToken
        });

    } catch (err: any) {
        console.error('Refresh token error:', err);
        if (err.name === 'JsonWebTokenError') {
            res.status(401).json({ message: 'Invalid refresh token' });
        } else if (err.name === 'TokenExpiredError') {
            res.status(401).json({ message: 'Refresh token expired' });
        } else {
            res.status(500).json({ message: 'Internal server error' });
        }
    }
};
const logout = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
) => {
    try {
        if (!req.user || !req.token) {
            res.status(400).json({ message: 'No user or token found in request' });
        }
        req.user.tokens = req.user.tokens.filter((t: { token: string }) => t.token !== req.token);

        await req.user.save();

        res.clearCookie('utoken');

        res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
        next(error)
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};

const logoutAll = async (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
): Promise<void> => {
    try {
        if (!req.user || !req.token) {
            res.status(400).json({ message: 'No user or token found in request' });
            return
        }
        req.user.tokens = []

        await req.user.save();

        res.clearCookie('utoken');

        res.status(200).json({ message: 'Logged out successfully' });
    } catch (error) {
        next(error)
        console.error('Logout error:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
};


const getUserDetails = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
        const { slug } = req.params;
        if (req?.user.slug.toString() !== slug) {
            res.status(403).json({ message: 'Forbidden. You are not allowed to access this resource.' });
            return
        }
        res.status(200).json({ data: { user_name: req.user.user_name, email: req.user.email } });


    } catch (err) {
        console.error('Get User Error:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

const deleteUser = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
    try {
        const { slug } = req.params;
        if (req?.user.slug.toString() !== slug) {
            res.status(403).json({
                message: 'Forbidden. You are not allowed to access this resource.'
            });
            return;
        }

        const deletedUser = await User.findOneAndDelete({ slug });
        if (!deletedUser) {
            res.status(404).json({ message: 'User not found.' });
            return;
        }

        res.status(200).json({ message: 'User deleted successfully' });

    } catch (err) {
        console.error('Delete error:', err);
        next(err);
        res.status(500).json({ message: 'Server error.' });
    }
};

const updateUserDetails = async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
        const { slug } = req.params;

        const user = await User.findOne({ slug });
        if (!user) {
            res.status(404).json({ message: 'User not found' });
            return;
        }

        if (req.user.slug !== slug) {
            res.status(403).json({ message: 'Forbidden: Not your account' });
            return;
        }

        const protectedFields = ['name', 'email', 'password'];
        const updates = Object.keys(req.body);

        const hasInvalidField = updates.some(field => protectedFields.includes(field));
        if (hasInvalidField) {
            res.status(400).json({ message: 'You cannot update name, email, or password.' });
            return;
        }
        updates.forEach(field => {
            if (req.body[field] === null) {
                user.set(field, undefined); // Remove field
            } else {
                user.set(field, req.body[field]); // Add or update field
            }
        });

        await user.save();

        res.status(200).json({ message: 'User updated successfully', user });

    } catch (err) {
        console.error('Update error:', err);
        res.status(500).json({ message: 'Internal Server Error' });
    }
};

const requestPasswordReset = async (req: Request, res: Response) => {
    try {
        const { email } = req.body;

        const user = await User.findOne({ email });
        if (!user) { res.status(404).json({ message: 'User not found' }); return; };

        const token = jwt.sign(
            { userId: user._id },
            config.JWT_SECRET!,
            { expiresIn: config.JWT_EXPIRES_IN }
        );

        await PasswordResetToken.deleteMany({ userId: user._id });

        const resetToken = new PasswordResetToken({
            userId: user._id,
            token,
            expiresAt: new Date(Date.now() + 15 * 60 * 1000) // 15 min
        });
        await resetToken.save();

        const resetLink = `${process.env.BASE_URL}?token=${token}`;

        const mailOptions = {
            from: process.env.EMAIL_FROM!,
            to: email,
            subject: 'Password Reset Request',
            html: `
        <p>You requested a password reset.</p>
        <p>Click the link below to reset your password:</p>
        <a href="${resetLink}">${resetLink}</a>
        <p>This link will expire in 15 minutes.</p>
      `
        };

        await transporter.sendMail(mailOptions);

        res.status(200).json({ message: 'Password reset link sent to your email.' });

    } catch (err) {
        console.error('Request Password Reset Error:', err);
        res.status(500).json({ message: 'Server error' });
    }
};

const resetPassword = async (req: Request, res: Response) => {
    try {
        const { resetToken, newPassword } = req.body;

        const decoded = jwt.verify(resetToken, config.JWT_SECRET!) as { userId: string };

        const tokenDoc = await PasswordResetToken.findOne({
            userId: decoded.userId,
            token: resetToken,
            expiresAt: { $gt: new Date() }
        });

        if (!tokenDoc) {
            res.status(400).json({ message: 'Invalid or expired token' });
            return;
        }

        const user = await User.findById(decoded.userId);
        if (!user) {
            res.status(404).json({ message: 'User not found' });
            return;
        }

        user.password = newPassword;
        await user.save();

        await PasswordResetToken.deleteOne({ _id: tokenDoc._id }); // Invalidate token after use

        res.status(200).json({ message: 'Password reset successful' });
    } catch (err) {
        console.error('Reset Password Error:', err);
        res.status(500).json({ message: 'Server error' });
    }
};


export { login, loginForm, logout, registerForm, registerNewUser, logoutAll, deleteUser, getUserDetails, updateUserDetails, refreshToken, requestPasswordReset, resetPassword }