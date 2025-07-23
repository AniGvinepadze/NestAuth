import { BadRequestException, Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from 'src/user/schema/user.schema';
import * as bcrypt from 'bcrypt';
import { SignUpDto } from './dto/sign-up.dto';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel('user') private readonly userModel: Model<User>,
    private jwtService: JwtService,
  ) {}

  async signUp({
    email,
    confrimPassword,
    firstName,
    lastName,
    password,
  }: SignUpDto) {
    const existUser = await this.userModel.findOne({ email });
    if (existUser) throw new BadRequestException('User already exists');

    if (password !== confrimPassword) {
      throw new BadRequestException(
        'Password and confirm password do not match',
      );
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    await this.userModel.create({
      email,
      password: hashedPassword,
      confirmPassword:password,
      firstName,
      lastName,
    });

    return ' user registered successfully'
  }
}
