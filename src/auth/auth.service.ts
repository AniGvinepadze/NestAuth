import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from 'src/user/schema/user.schema';
import * as bcrypt from 'bcrypt';
import { SignUpDto } from './dto/sign-up.dto';
import { SignInDto } from './dto/sign-in.dto';
import { themeReducer } from 'adminjs';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel('user') private readonly userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async signUp({
    email,
    confirmPassword,
    firstName,
    lastName,
    password,
  }: SignUpDto) {
    const existUser = await this.userModel.findOne({ email });
    if (existUser) throw new BadRequestException('User already exists');

    if (password !== confirmPassword) {
      throw new BadRequestException(
        'Password and confirm password do not match',
      );
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    await this.userModel.create({
      email,
      password: hashedPassword,
      firstName,
      lastName,
    });

    return ' user registered successfully';
  }

  async signIn({ email, password }: SignInDto) {
    const existUser = await this.userModel.findOne({ email });
    if (!existUser)
      throw new NotFoundException('email or password is incorrect');

    const isPassEqual = await bcrypt.comapre(password, existUser.password);
    if (!isPassEqual)
      throw new NotFoundException('email or password is incorrect');

    const payLoad = {
      userId: existUser._id,
    };

    const token = this.jwtService.sign(payLoad, { expiresIn: '1h' });

    return { message: 'user logged in successfully', token };
  }

 async getCurrentUser(userId: string) {
    const user = await this.userModel.findById(userId)
    if(!user) throw new NotFoundException("user not found")
        return user
  }
}
