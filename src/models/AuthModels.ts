
import mongoose, { Document, Model, Schema, model } from 'mongoose';
import slugify from 'slugify';
import { config } from '../config/test-config';
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

interface IToken {
    token: string;
}

export interface IUser extends Document {
    slug: string,
    user_name: string;
    email: string;
    password: string;
    tokens: Array<{ token: string }>;
    generateAuthToken(): Promise<string>;
    removeExpiredTokens(): Promise<void>;
}

interface IUserModel extends Model<IUser> {

}

const UserSchema = new Schema<IUser, IUserModel>({
    slug: { type: String, unique: true },
    user_name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    tokens: [{ token: { type: String, required: true } }]
}, { strict: false });

UserSchema.pre('save', async function (next) {
    const user = this as any;

    if (user.isModified('name') || user.isNew) {
        let baseSlug = slugify(user.user_name, { lower: true, strict: true });
        let slug = baseSlug;
        let count = 1;
        while (await mongoose.models.User.findOne({ slug })) {
            slug = `${baseSlug}-${count++}`;
        }

        user.slug = slug;
    }

    next();
});

UserSchema.methods.generateAuthToken = async function (): Promise<String> {
    const token = jwt.sign(
        { _id: this._id.toString() },
        config.JWT_SECRET,
        { expiresIn: config.JWT_EXPIRES_IN }
    );

    this.tokens = this.tokens.concat({ token });
    await this.save();
    return token;
}

UserSchema.pre<IUser>("save", async function (next) {
    if (this.isModified("password")) {
        this.password = await bcrypt.hash(this.password, config.SALT_ROUNDS);
    }
    next();
});

const User = model<IUser, IUserModel>('User', UserSchema);
export default User;