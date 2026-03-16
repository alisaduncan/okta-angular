/*
 * Copyright (c) 2017-Present, Okta, Inc. and/or its affiliates. All rights reserved.
 * The Okta software accompanied by this notice is provided pursuant to the Apache License, Version 2.0 (the "License.")
 *
 * You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0.
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *
 * See the License for the specific language governing permissions and limitations under the License.
 */

import { Injectable, Injector, inject } from '@angular/core';
import {
  CanActivate,
  CanActivateChild,
  CanActivateFn,
  CanActivateChildFn,
  CanMatchFn,
  ActivatedRouteSnapshot,
  RouterStateSnapshot,
  Router,
  NavigationStart, 
  Event,
  Route,
  Data
} from '@angular/router';
import { filter } from 'rxjs/operators';

import { OktaAuth, AuthState, TokenParams } from '@okta/okta-auth-js';
import { OktaAuthConfigService } from './services/auth-config.service';
import { AuthRequiredFunction, OKTA_AUTH } from './models/okta.config';

/**
 * Service that handles authentication logic for route guards
 */
@Injectable({ providedIn: 'root' })
export class OktaAuthGuard implements CanActivate, CanActivateChild {
  private state!: RouterStateSnapshot;
  private routeData!: Data;
  private onAuthRequired?: AuthRequiredFunction;
  private oktaAuth = inject<OktaAuth>(OKTA_AUTH);
  private injector = inject(Injector);

  constructor() {
    const configService = inject(OktaAuthConfigService);
    const config = configService.getConfig();
    if (!config) {
      throw new Error('Okta config is not provided');
    }
    this.onAuthRequired = config.onAuthRequired;

    // Unsubscribe updateAuthStateListener when route change
    const router = this.injector.get(Router);
    router.events.pipe(
      filter((e: Event) => e instanceof NavigationStart && this.state && this.state.url !== e.url)
    ).subscribe(() => {
      this.oktaAuth.authStateManager.unsubscribe(this.updateAuthStateListener);
    });
  }

  async canMatch(route: Route): Promise<boolean> {
    const onAuthRequiredOverride = route.data?.['onAuthRequired'];
    const currentOnAuthRequired = onAuthRequiredOverride || this.onAuthRequired;

    const isAuthenticated = await this.isAuthenticated(route.data);
    if (isAuthenticated) {
      return true;
    }

    const router = this.injector.get(Router);
    const nav = router.getCurrentNavigation();
    const originalUri = nav ? nav.extractedUrl.toString() : undefined;
    await this.handleLogin(originalUri, route.data, currentOnAuthRequired);

    return false;
  }

  /**
   * Gateway for protected route. Returns true if there is a valid idToken,
   * otherwise it will cache the route and start the login flow.
   * @param route
   * @param state
   */
  async canActivate(route: ActivatedRouteSnapshot, state: RouterStateSnapshot): Promise<boolean> {
    // Track states for current route
    this.state = state;
    this.routeData = route.data;
    const onAuthRequiredOverride = route.data && route.data['onAuthRequired'];
    const currentOnAuthRequired = onAuthRequiredOverride || this.onAuthRequired;

    // Protect the route after accessing
    this.oktaAuth.authStateManager.subscribe(this.updateAuthStateListener);
    const isAuthenticated = await this.isAuthenticated(route.data);
    if (isAuthenticated) {
      return true;
    }

    await this.handleLogin(state.url, route.data, currentOnAuthRequired);

    return false;
  }

  async canActivateChild(
    route: ActivatedRouteSnapshot,
    state: RouterStateSnapshot
  ): Promise<boolean> {
    return this.canActivate(route, state);
  }

  async isAuthenticated(routeData?: Data, authState?: AuthState | null): Promise<boolean> {
    const isAuthenticated = authState ? authState?.isAuthenticated : await this.oktaAuth.isAuthenticated();
    let res = isAuthenticated;
    if (routeData?.['okta']?.['acrValues']) {
      if (!authState) {
        authState = this.oktaAuth.authStateManager.getAuthState();
      }
      res = authState?.idToken?.claims.acr === routeData?.['okta']?.['acrValues'];
    }
    return res ?? false;
  }

  async handleLogin(originalUri?: string, routeData?: Data, onAuthRequired?: AuthRequiredFunction): Promise<void> {
    // Store the current path
    if (originalUri) {
      this.oktaAuth.setOriginalUri(originalUri);
    }

    const options: TokenParams = {};
    if (routeData?.['okta']?.['acrValues']) {
      // eslint-disable-next-line @typescript-eslint/ban-ts-comment
      // @ts-ignore Supports auth-js >= 7.1.0
      options.acrValues = routeData['okta']['acrValues'];
    }

    const authRequiredFn = onAuthRequired || this.onAuthRequired;
    if (authRequiredFn) {
      authRequiredFn(this.oktaAuth, this.injector, options);
    } else {
      this.oktaAuth.signInWithRedirect(options);
    }
  }

  private updateAuthStateListener = async (authState: AuthState) => {
    const isAuthenticated = await this.isAuthenticated(this.routeData, authState);
    if (!isAuthenticated) {
      this.handleLogin(this.state.url, this.routeData);
    }
  };
}

/**
 * Functional guard for canActivate
 */
export const canActivateAuthGuard: CanActivateFn = (route: ActivatedRouteSnapshot, state: RouterStateSnapshot) => {
  const guardService = inject(OktaAuthGuard);
  return guardService.canActivate(route, state);
};

/**
 * Functional guard for canActivateChild
 */
export const canActivateChildAuthGuard: CanActivateChildFn = (route: ActivatedRouteSnapshot, state: RouterStateSnapshot) => {
  const guardService = inject(OktaAuthGuard);
  return guardService.canActivateChild(route, state);
};

/**
 * Functional guard for canMatch
 */
export const canMatchAuthGuard: CanMatchFn = (route: Route) => {
  const guardService = inject(OktaAuthGuard);
  return guardService.canMatch(route);
};

