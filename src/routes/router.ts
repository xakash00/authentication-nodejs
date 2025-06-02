import express from 'express';
import { isDBConnected } from '../config/db';
import { deleteUser, getUserDetails, login, loginForm, logout, logoutAll, registerForm, registerNewUser, requestPasswordReset, resetPassword, updateUserDetails } from '../controllers/userControllers';
import { getHomePage, getProducts } from '../controllers/cartController';
import { auth } from '../middlewares/auth';
import { ownerShipCheck } from '../middlewares/ownerShipCheck';

const router = express.Router();


router.use((req, res, next) => {
    if (!isDBConnected) {
        return res.status(503).render('fallback', { message: 'Database unavailable. Please try again later.' });
    }
    next();
});

//products
router.get('/', getHomePage)
router.get('/products', auth, getProducts)

//Auth
router.get('/register', registerForm)
router.post('/register', registerNewUser)
router.get('/login', loginForm)
router.post('/login', login)
router.get('/logout', auth, logout)
router.get('/logout-all', auth, logoutAll)
router.post('/reset-password', resetPassword)
router.post('/verify-password', requestPasswordReset);

//users
router.delete('/delete/:slug', ownerShipCheck, deleteUser)
router.get('/profile/:slug', ownerShipCheck, getUserDetails)
router.put('/profile/:slug', ownerShipCheck, updateUserDetails)

export default router;
