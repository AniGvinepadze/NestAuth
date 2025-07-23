import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';

@Injectable()
export class isAuthGuard implements CanActivate {
  constructor(private jwtService: JwtService) {}
  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const req = context.switchToHttp().getRequest();
    console.log('first');
    const token = this.getTokenFromHeaders(req.headers);
    if (!token) {
      return false;
    }

    try {
      const payLoad = this.jwtService.verify(token, {
        secret: process.env.JWT_SECRET,
      });
      req.userId = payLoad.userId;
    } catch (error) {
      throw new UnauthorizedException('permission denied');
    }

    return true;
  }

  getTokenFromHeaders(headers) {
    const authorization = headers['authorization'];
    if (!authorization) return null;

    const [type, token] = authorization.split(' ');
    return type === 'Bearer' ? token : null;
  }
}
