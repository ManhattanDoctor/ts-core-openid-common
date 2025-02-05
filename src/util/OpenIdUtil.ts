import { OpenIdRequestHeaderUndefinedError, OpenIdRequestUndefinedError } from '../error';
import * as _ from 'lodash';

export class OpenIdUtil {
    // --------------------------------------------------------------------------
    //
    //  Static Methods
    //
    // --------------------------------------------------------------------------

    public static extractFromRequest(request: any): string {
        if (_.isNil(request)) {
            throw new OpenIdRequestUndefinedError();
        }
        let headers = request.headers;
        if (_.isNil(headers)) {
            throw new OpenIdRequestHeaderUndefinedError();
        }
        let authorization = headers.authorization;
        if (_.isEmpty(authorization)) {
            throw new OpenIdRequestHeaderUndefinedError();
        }
        let array = authorization.split(' ');
        return array[0].toLowerCase() === 'bearer' ? array[1] : null;
    }
}
