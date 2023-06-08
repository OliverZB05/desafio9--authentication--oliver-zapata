import passport from 'passport';
import local from 'passport-local';
import GitHubStrategy from 'passport-github2';
import userModel from '../dao/models/users.js';
import { createHash, isValidPassword } from '../utils.js';

const LocalStrategy = local.Strategy;

const initializePassport = () => {

    //======= Lógica de register en passport =======
    passport.use('register', new LocalStrategy({
        usernameField: 'email',
        passReqToCallback: true
    }, async (req, username, password, done) => {
        const { first_name, last_name, email, age } = req.body;
        try {
        const user = await userModel.findOne({ email: username });
    
        if (user) {
            return done(null, false, { message: 'El correo pertenece a un usuario ya registrado' })
        }
    
        let role;
        if(email === "adminCoder@coder.com" && password === "adminCod3r123"){
            role = "admin";
        }
        else {
            role = "usuario";
        }

        const userToSave = {
            first_name,
            last_name,
            email,
            age,
            password: createHash(password),
            role
        }
        
        const result = await userModel.create(userToSave);
        return done(null, result)
    
        } catch (error) {
        return done(`Error al obtener el usuario: ${error}`)
        }
    }));
    //======= Lógica de register en passport =======


    //======= Lógica de login en passport =======
    passport.use('login', new LocalStrategy({
        usernameField: 'email'
    }, async (username, password, done) => {
        try {
        const user = await userModel.findOne({ email: username });
    
        if (!user) {
            return done(null, false, { message: 'Este correo no coincide con ningún usuario registrado, por favor regístrese antes de iniciar sesión' });
        }
    
        if (!isValidPassword(user, password)) {
            return done(null, false, { message: 'Contraseña incorrecta' });
        } else {
            return done(null, user);
        }
        
        } catch (error) {
        return done(`Error al obtener el usuario: ${error}`)
        }
    }));
    //======= Lógica de login en passport =======


    //======= Lógica de registro con github en passport =======
    passport.use('github', new GitHubStrategy({
        clientID: "Iv1.ad3077c6cea461c0",
        clientSecret: "52e9e374d314ec5d4b39159799ea43d6ef83752c",
        callbackURL: "http://localhost:8080/api/sessions/github-callback",
        scope: ['user:email']
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            const email = profile.emails[0].value;
            const user = await userModel.findOne({ email })

            if (!user) {
                const newUser = {
                    first_name: profile.username,
                    name: profile.username,
                    last_name: '',
                    age: 18,
                    email,
                    password: '',
                    role: 'usuario'
                }

                const result = await userModel.create(newUser);
                done(null, result);
            } else {
                done(null, user);
            }
        } catch (error) {
            return done(error);
        }
    }));
    //======= Lógica de registro con github en passport =======


    passport.serializeUser((user, done) => {
        done(null, user._id);
    });

    passport.deserializeUser(async (id, done) => {
        const user = await userModel.findById(id);
        done(null, user);
    });
};

export default initializePassport;