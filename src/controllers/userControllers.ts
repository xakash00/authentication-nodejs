import { Request, Response, NextFunction } from 'express';
import User from '../models/AuthModels';
import { AuthenticatedRequest } from '../middlewares/auth';
const bcrypt = require('bcrypt');

const registerForm = (req: Request, res: Response): void => {
    res.render('register');
};

const loginForm = (req: Request, res: Response): void => {
    res.render('login');
};

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

        const token = await user.generateAuthToken();

        res.cookie("utoken", token, {
            expires: new Date(Date.now() + 600000),
            httpOnly: true,
        });

        res.status(201).json({
            message: 'Login successful.',
            accessToken: token,
        });

    } catch (e) {
        console.error('Login error:', e);
        res.status(500).json({
            message: 'Something went wrong.',
        });
    }
}


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


export { login, loginForm, logout, registerForm, registerNewUser, logoutAll, deleteUser, getUserDetails, updateUserDetails }