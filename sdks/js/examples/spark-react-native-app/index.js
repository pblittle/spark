/**
 * @format
 */

import '@azure/core-asynciterator-polyfill';
import { Buffer } from 'buffer';
import { AppRegistry } from 'react-native';
import 'react-native-get-random-values';
import 'text-encoding';
import App from './App';
import { name as appName } from './app.json';
global.Buffer = Buffer;

AppRegistry.registerComponent(appName, () => App);
