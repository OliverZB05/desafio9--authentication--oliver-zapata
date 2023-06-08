import { Router } from 'express';
import userModel from '../../dao/models/users.js';
import passport from 'passport';
import { createHash } from '../../utils.js';

const router = Router();

//========= Register =========
router.post('/register', (req, res, next) => {
    passport.authenticate('register', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.send({ status: 'error', message: info.message });
    req.logIn(user, err => {
        if (err) return next(err);
        res.send({ status: 'success', message: 'User registered' });
    });
    })(req, res, next);
});
//========= Register =========


//========= Login =========
router.post('/login', (req, res, next) => {
    passport.authenticate('login', (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.send({ status: 'error', message: info.message });
    req.logIn(user, err => {
        if (err) return next(err);
        res.send({ status: 'success', message: 'Login success' });
    });
    })(req, res, next);
});
//========= Login =========


//========= Github =========
router.get('/github', passport.authenticate(
    'github', { scope: ['user:email'] }
), async (req, res) => {
    res.send({ status: "success", message: "User registered" })
});

router.get('/github-callback', passport.authenticate(
    'github', { failureRedirect: '/login' }
), async (req, res) => {
    req.session.user = req.user;
    res.redirect('/products');
})
//========= Github =========


//========= Reset =========
router.post('/reset', async(req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) return res.status(400).send({ status: 'error', error: 'Incomplete values' });

        const user = await userModel.findOne({ email });

        if (!user) return res.status(400).send({ status: 'error', error: 'Este correo no coincide con ningún usuario registrado' });

        user.password = createHash(password);

        await userModel.updateOne({ email }, user);

        res.send({ status: 'success', message: 'Password reset' })
    } catch (error) {
        res.status(500).send({ status: 'error', error: error.message });   
    }
})
//========= Reset =========


//========= Logout =========
router.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) return res.status(500).send({ status: 'error', error: 'Logout fail' });
        res.redirect('/')
    })
});
//========= Logout =========

export default router;

