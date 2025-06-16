import express from 'express';
import { isDBConnected } from '../config/db';

import * as userCtrl from '../controllers/userControllers';
import * as cartCtrl from '../controllers/cartController';
import * as mgrCtrl from '../controllers/ManagerController';
import * as leaveCtrl from '../controllers/leaveController';

import { auth } from '../middlewares/auth';
import { ownerShipCheck } from '../middlewares/ownerShipCheck';
import { authorizeRoles } from '../middlewares/roles';

const router = express.Router();

router.use((req, res, next) => {
    if (!isDBConnected) {
        return res
            .status(503)
            .render('fallback', { message: 'Database unavailable. Please try again later.' });
    }
    next();
});

router.get('/', cartCtrl.getHomePage);
router.get('/products', auth, cartCtrl.getProducts);

/* -------------------------------------------------
 * Auth
 * ------------------------------------------------- */
router
    .route('/auth/register')
    .get(userCtrl.registerForm)
    .post(userCtrl.registerNewUser);

router
    .route('/auth/login')
    .get(userCtrl.loginForm)
    .post(userCtrl.login);

router.post('/auth/logout', auth, userCtrl.logout);
router.post('/auth/logout-all', auth, userCtrl.logoutAll);

router.post('/auth/password/otp', userCtrl.requestPasswordReset);
router.post('/auth/password/reset', userCtrl.resetPassword);

/* -------------------------------------------------
 * Users – self‑service
 * ------------------------------------------------- */
router
    .route('/users/:slug')
    .all(ownerShipCheck)
    .get(userCtrl.getUserDetails)
    .put(userCtrl.updateUserDetails)
    .delete(userCtrl.deleteUser);

/* -------------------------------------------------
 * Leave requests (self)
 * ------------------------------------------------- */
router.post('/users/:slug/leaves', auth, leaveCtrl.requestLeave);
router.get('/users/:slug/leaves', auth, leaveCtrl.getEmployeeLeaves);
router.get('/users/:slug/leaves/approved', auth, leaveCtrl.getApprovedLeaves);
router.get('users/leaves/me', auth, leaveCtrl.getUserOwnLeaves);
router.get('/users/leave-data', auth, leaveCtrl.getUserLeaveData)


/* =================================================
 * Manager‑only area – every route starts with /manager
 * ================================================= */
router.use('/manager', auth, authorizeRoles('manager'));  // gatekeeper

router.get('/manager/dashboard', mgrCtrl.getManagerDashboard);

router.get('/manager/users', mgrCtrl.listAllUsersWithRoles);
router.patch('/manager/users/:slug/assign-manager', mgrCtrl.assignManager);
router.patch('/manager/users/:slug/leave-balance', leaveCtrl.updateLeaveBalance);

router.get('/manager/leaves/pending', leaveCtrl.getManagerPendingLeaves);
router.patch('/manager/leaves/review', leaveCtrl.reviewLeave);

router.get('/manager/teams/members', mgrCtrl.getMyEmployees);
router.get('/manager/teams/stats', mgrCtrl.getMyTeamWithLeaveStats);

export default router;
